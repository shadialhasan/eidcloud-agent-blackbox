<?php

declare(strict_types=1);

namespace EidCloud\AgentBlackbox\Chain;

use EidCloud\AgentBlackbox\Events\AgentEvent;

/**
 * MerkleChain manages cryptographic block-hash chaining across events,
 * enabling tamper-evident validation and audit proof generation.
 */
class MerkleChain
{
    private ?string $lastHash = null;

    public function __construct(?string $initialHash = null)
    {
        $this->lastHash = $initialHash;
    }

    public function getLastHash(): ?string
    {
        return $this->lastHash;
    }

    /**
     * Links and wraps a new event into the Merkle chain.
     */
    public function linkEvent(int $sequence, string $type, array $payload = [], array $metadata = []): AgentEvent
    {
        $event = new AgentEvent(
            sequence: $sequence,
            type: $type,
            payload: $payload,
            metadata: $metadata,
            previousHash: $this->lastHash
        );

        $this->lastHash = $event->getHash();
        return $event;
    }

    /**
     * Verifies the cryptographic integrity of an array of events.
     * 
     * @param AgentEvent[] $events
     * @return array{valid: bool, error: ?string, broken_at_sequence: ?int, broken_event_id: ?string, events_verified: int}
     */
    public static function verifyChain(array $events): array
    {
        if (empty($events)) {
            return [
                'valid' => true,
                'error' => null,
                'broken_at_sequence' => null,
                'broken_event_id' => null,
                'events_verified' => 0
            ];
        }

        $expectedPreviousHash = null;

        foreach ($events as $index => $event) {
            // Check sequence consistency
            if ($event->getSequence() !== $index + 1) {
                return [
                    'valid' => false,
                    'error' => sprintf(
                        'Sequence break detected at index %d: expected sequence %d, got %d',
                        $index,
                        $index + 1,
                        $event->getSequence()
                    ),
                    'broken_at_sequence' => $event->getSequence(),
                    'broken_event_id' => $event->getId(),
                    'events_verified' => $index
                ];
            }

            // Check previous hash matching
            if ($event->getPreviousHash() !== $expectedPreviousHash) {
                return [
                    'valid' => false,
                    'error' => sprintf(
                        'Previous hash mismatch at sequence %d (%s). Expected "%s", found "%s"',
                        $event->getSequence(),
                        $event->getId(),
                        $expectedPreviousHash ?? 'NULL (GENESIS)',
                        $event->getPreviousHash() ?? 'NULL (GENESIS)'
                    ),
                    'broken_at_sequence' => $event->getSequence(),
                    'broken_event_id' => $event->getId(),
                    'events_verified' => $index
                ];
            }

            // Check self hash validity
            $computedHash = $event->computeHash();
            if ($event->getHash() !== $computedHash) {
                return [
                    'valid' => false,
                    'error' => sprintf(
                        'Cryptographic hash corruption at sequence %d (%s). Stored "%s", computed "%s"',
                        $event->getSequence(),
                        $event->getId(),
                        $event->getHash(),
                        $computedHash
                    ),
                    'broken_at_sequence' => $event->getSequence(),
                    'broken_event_id' => $event->getId(),
                    'events_verified' => $index
                ];
            }

            $expectedPreviousHash = $event->getHash();
        }

        return [
            'valid' => true,
            'error' => null,
            'broken_at_sequence' => null,
            'broken_event_id' => null,
            'events_verified' => count($events)
        ];
    }
}
