<?php

declare(strict_types=1);

namespace EidCloud\AgentBlackbox\Forensics;

use EidCloud\AgentBlackbox\Events\AgentEvent;

/**
 * CrashAnalyzer parses event streams to pinpoint exact failure causes,
 * tool execution deadlocks, unhandled exceptions, and anomalous metrics.
 */
class CrashAnalyzer
{
    /**
     * @param AgentEvent[] $events
     * @return array{
     *   has_crash: bool,
     *   fatal_event: ?array,
     *   root_cause: ?string,
     *   culprit_tool: ?array,
     *   last_actions: array,
     *   total_tokens: array{prompt: int, completion: int, total: int},
     *   execution_duration_ms: float,
     *   event_counts: array<string, int>
     * }
     */
    public static function analyze(array $events): array
    {
        $hasCrash = false;
        $fatalEvent = null;
        $rootCause = null;
        $culpritTool = null;
        $eventCounts = [];
        $totalTokens = ['prompt' => 0, 'completion' => 0, 'total' => 0];

        $startTimestamp = !empty($events) ? $events[0]->getTimestampNs() : 0;
        $endTimestamp = !empty($events) ? end($events)->getTimestampNs() : 0;
        $durationMs = ($endTimestamp > $startTimestamp) ? ($endTimestamp - $startTimestamp) / 1_000_000 : 0.0;

        $lastToolInvocation = null;

        foreach ($events as $event) {
            $type = $event->getType();
            $eventCounts[$type] = ($eventCounts[$type] ?? 0) + 1;
            $payload = $event->getPayload();

            // Track tokens
            if ($type === 'token_expenditure' || isset($payload['tokens'])) {
                $tokens = $payload['tokens'] ?? $payload;
                $p = (int)($tokens['prompt'] ?? $tokens['prompt_tokens'] ?? 0);
                $c = (int)($tokens['completion'] ?? $tokens['completion_tokens'] ?? 0);
                $t = (int)($tokens['total'] ?? $tokens['total_tokens'] ?? ($p + $c));

                $totalTokens['prompt'] += $p;
                $totalTokens['completion'] += $c;
                $totalTokens['total'] += $t;
            }

            // Track tool invocations
            if ($type === 'tool_invocation' || $type === 'tool_call') {
                $lastToolInvocation = [
                    'sequence' => $event->getSequence(),
                    'id' => $event->getId(),
                    'timestamp' => $event->getIsoTimestamp(),
                    'tool' => $payload['tool'] ?? $payload['name'] ?? 'unknown',
                    'arguments' => $payload['arguments'] ?? $payload['input'] ?? []
                ];
            }

            // Detect errors and crashes
            if (in_array($type, ['error', 'crash', 'exception', 'fatal_error'], true)) {
                $hasCrash = true;
                $fatalEvent = [
                    'sequence' => $event->getSequence(),
                    'id' => $event->getId(),
                    'type' => $type,
                    'timestamp' => $event->getIsoTimestamp(),
                    'message' => $payload['message'] ?? $payload['error'] ?? 'Unknown critical error',
                    'exception_class' => $payload['class'] ?? $payload['exception'] ?? null,
                    'file' => $payload['file'] ?? null,
                    'line' => $payload['line'] ?? null,
                    'trace' => $payload['trace'] ?? null,
                    'details' => $payload
                ];

                $rootCause = $fatalEvent['message'];
                if ($lastToolInvocation !== null) {
                    $culpritTool = $lastToolInvocation;
                }
            }
        }

        // Get last 5 actions for context
        $lastActions = array_map(function (AgentEvent $e) {
            return [
                'sequence' => $e->getSequence(),
                'type' => $e->getType(),
                'timestamp' => $e->getIsoTimestamp(),
                'summary' => self::summarizeEvent($e)
            ];
        }, array_slice($events, -5));

        return [
            'has_crash' => $hasCrash,
            'fatal_event' => $fatalEvent,
            'root_cause' => $rootCause,
            'culprit_tool' => $culpritTool,
            'last_actions' => $lastActions,
            'total_tokens' => $totalTokens,
            'execution_duration_ms' => round($durationMs, 3),
            'event_counts' => $eventCounts
        ];
    }

    private static function summarizeEvent(AgentEvent $e): string
    {
        $p = $e->getPayload();
        return match ($e->getType()) {
            'prompt_input' => 'Prompt: ' . mb_substr((string)($p['prompt'] ?? $p['content'] ?? ''), 0, 50) . '...',
            'context_snapshot' => 'Context snapshot: ' . count($p['context'] ?? $p['messages'] ?? []) . ' items',
            'tool_invocation', 'tool_call' => 'Tool call: ' . ($p['tool'] ?? $p['name'] ?? 'unknown'),
            'shell_execution' => 'Exec: ' . ($p['command'] ?? 'command'),
            'filesystem_mutation' => 'FS ' . ($p['action'] ?? 'change') . ': ' . ($p['path'] ?? 'file'),
            'network_egress' => 'HTTP ' . ($p['method'] ?? 'GET') . ' ' . ($p['url'] ?? ''),
            'token_expenditure' => 'Tokens: ' . ($p['total'] ?? 0),
            'error', 'crash', 'exception' => 'CRASH: ' . ($p['message'] ?? $p['error'] ?? 'failure'),
            default => 'Event ' . $e->getType()
        };
    }
}
