<?php

declare(strict_types=1);

namespace EidCloud\AgentBlackbox\Reports;

use EidCloud\AgentBlackbox\Events\AgentEvent;
use EidCloud\AgentBlackbox\Chain\MerkleChain;
use EidCloud\AgentBlackbox\Forensics\CrashAnalyzer;

/**
 * Generates an interactive forensic HTML report with waterfall timeline,
 * cryptographic verification badges, and token metrics.
 */
class HtmlIncidentReport
{
    /**
     * @param AgentEvent[] $events
     * @param string $sessionTitle
     * @return string HTML report content
     */
    public static function generate(array $events, string $sessionTitle = 'Agent Execution Incident Report'): string
    {
        $verification = MerkleChain::verifyChain($events);
        $analysis = CrashAnalyzer::analyze($events);

        $eventsCount = count($events);
        $statusBadge = $analysis['has_crash']
            ? '<span class="badge badge-danger">CRASH DETECTED</span>'
            : '<span class="badge badge-success">COMPLETED NORMALLY</span>';

        $chainBadge = $verification['valid']
            ? '<span class="badge badge-success">MERKLE CHAIN VERIFIED</span>'
            : '<span class="badge badge-danger">CHAIN INTEGRITY BROKEN</span>';

        $rowsHtml = '';
        foreach ($events as $event) {
            $type = htmlspecialchars($event->getType());
            $badgeClass = match ($event->getType()) {
                'error', 'crash', 'exception' => 'badge-danger',
                'tool_invocation', 'shell_execution' => 'badge-warning',
                'network_egress' => 'badge-info',
                'token_expenditure' => 'badge-primary',
                default => 'badge-secondary'
            };

            $payloadJson = htmlspecialchars(json_encode($event->getPayload(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $hashShort = htmlspecialchars(substr($event->getHash(), 0, 8) . '...' . substr($event->getHash(), -8));
            $prevHashShort = $event->getPreviousHash()
                ? htmlspecialchars(substr($event->getPreviousHash(), 0, 8) . '...' . substr($event->getPreviousHash(), -8))
                : '<span class="text-muted">GENESIS</span>';

            $rowsHtml .= "
            <tr class=\"event-row\">
                <td><strong>#{$event->getSequence()}</strong></td>
                <td><small>{$event->getIsoTimestamp()}</small></td>
                <td><span class=\"badge {$badgeClass}\">{$type}</span></td>
                <td>
                    <details>
                        <summary class=\"payload-summary\">View Payload (" . count($event->getPayload()) . " keys)</summary>
                        <pre class=\"code-block\">{$payloadJson}</pre>
                    </details>
                </td>
                <td><code title=\"{$event->getHash()}\">{$hashShort}</code></td>
                <td><code title=\"{$event->getPreviousHash()}\">{$prevHashShort}</code></td>
            </tr>";
        }

        $crashSection = '';
        if ($analysis['has_crash'] && $analysis['fatal_event']) {
            $fatal = $analysis['fatal_event'];
            $rootCause = htmlspecialchars($analysis['root_cause'] ?? 'Unknown');
            $culpritInfo = '';
            if ($analysis['culprit_tool']) {
                $cTool = htmlspecialchars($analysis['culprit_tool']['tool']);
                $cArgs = htmlspecialchars(json_encode($analysis['culprit_tool']['arguments'], JSON_PRETTY_PRINT));
                $culpritInfo = "
                <div class=\"culprit-box\">
                    <h4>Culprit Tool Invocation (Sequence #{$analysis['culprit_tool']['sequence']})</h4>
                    <p><strong>Tool:</strong> <code>{$cTool}</code></p>
                    <pre class=\"code-block\">{$cArgs}</pre>
                </div>";
            }

            $traceHtml = !empty($fatal['trace']) ? '<pre class="code-block trace">' . htmlspecialchars(is_array($fatal['trace']) ? implode("\n", $fatal['trace']) : $fatal['trace']) . '</pre>' : '';

            $crashSection = "
            <div class=\"panel panel-danger\">
                <h2>🚨 Fatal Crash Forensics</h2>
                <p><strong>Root Cause:</strong> <span class=\"text-danger\">{$rootCause}</span></p>
                <p><strong>Failed At Event:</strong> Sequence #{$fatal['sequence']} ({$fatal['timestamp']})</p>
                {$culpritInfo}
                {$traceHtml}
            </div>";
        }

        $tokens = $analysis['total_tokens'];
        $durationMs = $analysis['execution_duration_ms'];

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$sessionTitle} | EidCloud Blackbox</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #06b6d4;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
        }
        .container {
            max-width: 1300px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        h1 {
            margin: 0;
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .badges {
            display: flex;
            gap: 10px;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }
        .badge-danger { background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--danger); }
        .badge-success { background-color: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--success); }
        .badge-warning { background-color: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid var(--warning); }
        .badge-info { background-color: rgba(6, 182, 212, 0.2); color: #67e8f9; border: 1px solid var(--info); }
        .badge-primary { background-color: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid var(--primary); }
        .badge-secondary { background-color: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid var(--text-muted); }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .card-label {
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        .card-value {
            font-size: 1.5rem;
            font-weight: bold;
            margin-top: 4px;
        }

        .panel {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .panel-danger {
            border-color: var(--danger);
            background-color: rgba(239, 68, 68, 0.05);
        }
        .culprit-box {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
            border-left: 4px solid var(--warning);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background-color: rgba(255, 255, 255, 0.02);
            color: var(--text-muted);
            font-weight: 600;
        }
        .code-block {
            background-color: #0b1120;
            color: #38bdf8;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            max-height: 250px;
        }
        .payload-summary {
            cursor: pointer;
            color: var(--primary);
        }
        .text-muted { color: var(--text-muted); }
        .text-danger { color: #f87171; font-weight: bold; }
        footer {
            margin-top: 32px;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>⬛ EidCloud Agent Black Box</h1>
                <p class="text-muted">Forensic Flight Recorder Incident Investigation</p>
            </div>
            <div class="badges">
                {$statusBadge}
                {$chainBadge}
            </div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div class="card-label">Total Events Recorded</div>
                <div class="card-value">{$eventsCount}</div>
            </div>
            <div class="card">
                <div class="card-label">Execution Duration</div>
                <div class="card-value">{$durationMs} ms</div>
            </div>
            <div class="card">
                <div class="card-label">Prompt Tokens</div>
                <div class="card-value">{$tokens['prompt']}</div>
            </div>
            <div class="card">
                <div class="card-label">Completion Tokens</div>
                <div class="card-value">{$tokens['completion']}</div>
            </div>
            <div class="card">
                <div class="card-label">Total Tokens</div>
                <div class="card-value">{$tokens['total']}</div>
            </div>
        </div>

        {$crashSection}

        <div class="panel">
            <h2>📜 Event Execution Waterfall Timeline</h2>
            <table>
                <thead>
                    <tr>
                        <th>Seq</th>
                        <th>Timestamp (UTC)</th>
                        <th>Type</th>
                        <th>Payload Context</th>
                        <th>Merkle Block Hash</th>
                        <th>Previous Hash</th>
                    </tr>
                </thead>
                <tbody>
                    {$rowsHtml}
                </tbody>
            </table>
        </div>

        <footer>
            Generated by <strong>EidCloud Agent Black Box v1.0.0</strong> &bull; Author: Eng. MHD. Shadi AL-Hasan
        </footer>
    </div>
</body>
</html>
HTML;
    }
}
