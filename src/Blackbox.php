<?php

declare(strict_types=1);

namespace EidCloud\AgentBlackbox;

use EidCloud\AgentBlackbox\Chain\MerkleChain;
use EidCloud\AgentBlackbox\Events\AgentEvent;
use EidCloud\AgentBlackbox\Forensics\CrashAnalyzer;
use EidCloud\AgentBlackbox\Reports\HtmlIncidentReport;
use RuntimeException;
use Throwable;

/**
 * Main AI Flight Recorder engine for Autonomous Agents.
 */
class Blackbox
{
    private string $sessionId;
    private ?string $logPath;
    private MerkleChain $chain;
    /** @var AgentEvent[] */
    private array $events = [];
    private int $sequence = 0;
    /** @var resource|null */
    private $fileHandle = null;

    public function __construct(?string $logPath = null, ?string $sessionId = null)
    {
        $this->sessionId = $sessionId ?? bin2hex(random_bytes(8));
        $this->logPath = $logPath;
        $this->chain = new MerkleChain();

        if ($this->logPath !== null) {
            $dir = dirname($this->logPath);
            if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
                throw new RuntimeException(sprintf('Failed to create log directory "%s"', $dir));
            }
            $handle = fopen($this->logPath, 'a');
            if ($handle === false) {
                throw new RuntimeException(sprintf('Failed to open log file "%s" for writing', $this->logPath));
            }
            $this->fileHandle = $handle;
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    public function close(): void
    {
        if ($this->fileHandle !== null && is_resource($this->fileHandle)) {
            fflush($this->fileHandle);
            fclose($this->fileHandle);
            $this->fileHandle = null;
        }
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    /**
     * @return AgentEvent[]
     */
    public function getEvents(): array
    {
        return $this->events;
    }

    /**
     * Records a generic event into the flight recorder.
     */
    public function record(string $type, array $payload = [], array $metadata = []): AgentEvent
    {
        $this->sequence++;
        $metadata['session_id'] = $this->sessionId;

        $event = $this->chain->linkEvent($this->sequence, $type, $payload, $metadata);
        $this->events[] = $event;

        if ($this->fileHandle !== null) {
            $jsonLine = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
            fwrite($this->fileHandle, $jsonLine);
            fflush($this->fileHandle);
        }

        return $event;
    }

    public function recordPromptInput(string $prompt, array $parameters = []): AgentEvent
    {
        return $this->record('prompt_input', [
            'prompt' => $prompt,
            'parameters' => $parameters
        ]);
    }

    public function recordContextSnapshot(array $messages, array $systemState = []): AgentEvent
    {
        return $this->record('context_snapshot', [
            'messages_count' => count($messages),
            'messages' => $messages,
            'system_state' => $systemState
        ]);
    }

    public function recordToolInvocation(string $tool, array $arguments, ?string $callId = null): AgentEvent
    {
        return $this->record('tool_invocation', [
            'call_id' => $callId ?? bin2hex(random_bytes(6)),
            'tool' => $tool,
            'arguments' => $arguments
        ]);
    }

    public function recordShellExecution(string $command, ?int $exitCode = null, ?string $output = null, ?float $durationMs = null): AgentEvent
    {
        return $this->record('shell_execution', [
            'command' => $command,
            'exit_code' => $exitCode,
            'output' => $output,
            'duration_ms' => $durationMs
        ]);
    }

    public function recordFilesystemMutation(string $action, string $path, ?int $bytesChanged = null, ?string $checksum = null): AgentEvent
    {
        return $this->record('filesystem_mutation', [
            'action' => $action,
            'path' => $path,
            'bytes_changed' => $bytesChanged,
            'checksum' => $checksum
        ]);
    }

    public function recordNetworkEgress(string $method, string $url, int $statusCode, ?int $bytesSent = null, ?int $bytesReceived = null, ?float $durationMs = null): AgentEvent
    {
        return $this->record('network_egress', [
            'method' => strtoupper($method),
            'url' => $url,
            'status_code' => $statusCode,
            'bytes_sent' => $bytesSent,
            'bytes_received' => $bytesReceived,
            'duration_ms' => $durationMs
        ]);
    }

    public function recordTokenExpenditure(int $promptTokens, int $completionTokens, ?string $model = null): AgentEvent
    {
        return $this->record('token_expenditure', [
            'model' => $model,
            'prompt_tokens' => $promptTokens,
            'completion_tokens' => $completionTokens,
            'total_tokens' => $promptTokens + $completionTokens
        ]);
    }

    public function recordCrash(Throwable $exception, array $additionalContext = []): AgentEvent
    {
        return $this->record('crash', [
            'message' => $exception->getMessage(),
            'class' => get_class($exception),
            'code' => $exception->getCode(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => explode("\n", $exception->getTraceAsString()),
            'context' => $additionalContext
        ]);
    }

    /**
     * Verifies the cryptographic Merkle chain for recorded events.
     */
    public function verify(): array
    {
        return MerkleChain::verifyChain($this->events);
    }

    /**
     * Conducts forensic crash analysis on events.
     */
    public function analyzeCrash(): array
    {
        return CrashAnalyzer::analyze($this->events);
    }

    /**
     * Exports an HTML incident investigation report.
     */
    public function exportHtmlReport(?string $outputPath = null, string $title = 'Agent Execution Incident Report'): string
    {
        $html = HtmlIncidentReport::generate($this->events, $title);
        if ($outputPath !== null) {
            file_put_contents($outputPath, $html);
        }
        return $html;
    }

    /**
     * Loads events from an existing JSON Lines flight recorder log file.
     * 
     * @return AgentEvent[]
     */
    public static function loadFlightLog(string $filePath): array
    {
        if (!file_exists($filePath)) {
            throw new RuntimeException(sprintf('Flight log file "%s" does not exist', $filePath));
        }

        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            throw new RuntimeException(sprintf('Failed to read flight log "%s"', $filePath));
        }

        $events = [];
        foreach ($lines as $lineNum => $line) {
            $data = json_decode($line, true);
            if (!is_array($data)) {
                throw new RuntimeException(sprintf('Malformed JSON on line %d of flight log "%s"', $lineNum + 1, $filePath));
            }
            $events[] = AgentEvent::fromArray($data);
        }

        return $events;
    }
}
