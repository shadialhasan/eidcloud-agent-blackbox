<?php

declare(strict_types=1);

namespace EidCloud\AgentBlackbox\Tests;

use EidCloud\AgentBlackbox\Blackbox;
use EidCloud\AgentBlackbox\Chain\MerkleChain;
use EidCloud\AgentBlackbox\Events\AgentEvent;
use EidCloud\AgentBlackbox\Forensics\CrashAnalyzer;
use EidCloud\AgentBlackbox\Reports\HtmlIncidentReport;
use RuntimeException;

class BlackboxTest
{
    private int $assertions = 0;

    private function assert(bool $condition, string $message): void
    {
        $this->assertions++;
        if (!$condition) {
            throw new RuntimeException("Assertion failed: " . $message);
        }
    }

    private function assertEquals(mixed $expected, mixed $actual, string $message): void
    {
        $this->assertions++;
        if ($expected !== $actual) {
            throw new RuntimeException("Assertion failed: {$message} (Expected: " . var_export($expected, true) . ", Got: " . var_export($actual, true) . ")");
        }
    }

    public function getAssertionsCount(): int
    {
        return $this->assertions;
    }

    public function testEventCreationAndHashing(): void
    {
        $event = new AgentEvent(1, 'prompt_input', ['prompt' => 'Hello AI']);
        $this->assertEquals(1, $event->getSequence(), 'Sequence matches');
        $this->assertEquals('prompt_input', $event->getType(), 'Type matches');
        $this->assert(strlen($event->getHash()) === 64, 'SHA-256 hash length is 64');
        $this->assertEquals($event->getHash(), $event->computeHash(), 'Self-computed hash matches');
    }

    public function testMerkleChainingIntegrity(): void
    {
        $chain = new MerkleChain();
        $e1 = $chain->linkEvent(1, 'prompt_input', ['prompt' => 'Task start']);
        $e2 = $chain->linkEvent(2, 'tool_invocation', ['tool' => 'bash', 'arguments' => ['ls -la']]);
        $e3 = $chain->linkEvent(3, 'token_expenditure', ['prompt_tokens' => 50, 'completion_tokens' => 20]);

        $this->assert($e1->getPreviousHash() === null, 'First event previous hash is null (genesis)');
        $this->assertEquals($e1->getHash(), $e2->getPreviousHash(), 'E2 points to E1 hash');
        $this->assertEquals($e2->getHash(), $e3->getPreviousHash(), 'E3 points to E2 hash');

        $verification = MerkleChain::verifyChain([$e1, $e2, $e3]);
        $this->assert($verification['valid'] === true, 'Chain verification succeeds');
        $this->assertEquals(3, $verification['events_verified'], '3 events verified');
    }

    public function testTamperDetection(): void
    {
        $chain = new MerkleChain();
        $e1 = $chain->linkEvent(1, 'prompt_input', ['prompt' => 'Original prompt']);
        $e2 = $chain->linkEvent(2, 'tool_invocation', ['tool' => 'exec', 'command' => 'safe_script']);

        // Tamper with e1 payload
        $tamperedE1 = new AgentEvent(
            1,
            'prompt_input',
            ['prompt' => 'MALICIOUS_PROMPT_INJECTED'],
            $e1->getMetadata(),
            $e1->getPreviousHash(),
            $e1->getTimestampNs(),
            $e1->getId(),
            $e1->getHash() // Stored hash kept same as original
        );

        $verification = MerkleChain::verifyChain([$tamperedE1, $e2]);
        $this->assert($verification['valid'] === false, 'Tampered event is detected as invalid');
        $this->assertEquals(1, $verification['broken_at_sequence'], 'Broken at sequence 1');
    }

    public function testCrashAnalysisAndCulpritIdentification(): void
    {
        $tempLog = tempnam(sys_get_temp_dir(), 'bb_');
        $bb = new Blackbox($tempLog);

        $bb->recordPromptInput("Calculate data");
        $bb->recordToolInvocation("sql_query", ["query" => "SELECT * FROM non_existent_table"]);
        
        try {
            throw new RuntimeException("Table 'non_existent_table' doesn't exist", 1045);
        } catch (\Throwable $e) {
            $bb->recordCrash($e);
        }

        $bb->close();

        $loadedEvents = Blackbox::loadFlightLog($tempLog);
        $this->assertEquals(3, count($loadedEvents), '3 events loaded from file');

        $analysis = CrashAnalyzer::analyze($loadedEvents);
        $this->assert($analysis['has_crash'] === true, 'Crash correctly identified');
        $this->assertEquals("Table 'non_existent_table' doesn't exist", $analysis['root_cause'], 'Root cause identified');
        $this->assert($analysis['culprit_tool'] !== null, 'Culprit tool identified');
        $this->assertEquals('sql_query', $analysis['culprit_tool']['tool'], 'Culprit tool name matches');

        // Clean up
        if (file_exists($tempLog)) {
            unlink($tempLog);
        }
    }

    public function testHtmlReportGeneration(): void
    {
        $bb = new Blackbox();
        $bb->recordPromptInput("Summarize incident");
        $bb->recordTokenExpenditure(120, 80, "gemini-pro");

        $html = $bb->exportHtmlReport();
        $this->assert(str_contains($html, '<!DOCTYPE html>'), 'Contains HTML doctype');
        $this->assert(str_contains($html, 'EidCloud Agent Black Box'), 'Contains title');
        $this->assert(str_contains($html, 'MERKLE CHAIN VERIFIED'), 'Contains verified badge');
    }
}
