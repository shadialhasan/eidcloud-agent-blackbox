<?php

declare(strict_types=1);

namespace EidCloud\AgentBlackbox\Events;

use JsonSerializable;

/**
 * Immutable flight recorder event with nanosecond-precision timestamp and cryptographic hashing.
 */
class AgentEvent implements JsonSerializable
{
    private string $id;
    private int $sequence;
    private int $timestampNs;
    private string $isoTimestamp;
    private string $type;
    private array $payload;
    private array $metadata;
    private ?string $previousHash;
    private ?string $hash;

    public function __construct(
        int $sequence,
        string $type,
        array $payload = [],
        array $metadata = [],
        ?string $previousHash = null,
        ?int $timestampNs = null,
        ?string $id = null,
        ?string $hash = null
    ) {
        $this->sequence = $sequence;
        $this->type = $type;
        $this->payload = $payload;
        $this->metadata = $metadata;
        $this->previousHash = $previousHash;
        
        $this->timestampNs = $timestampNs ?? (int) (hrtime(true));
        $this->isoTimestamp = gmdate('Y-m-d\TH:i:s') . '.' . sprintf('%06d', (int) ($this->timestampNs % 1_000_000_000 / 1000)) . 'Z';
        $this->id = $id ?? bin2hex(random_bytes(16));
        $this->hash = $hash ?? $this->computeHash();
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getSequence(): int
    {
        return $this->sequence;
    }

    public function getTimestampNs(): int
    {
        return $this->timestampNs;
    }

    public function getIsoTimestamp(): string
    {
        return $this->isoTimestamp;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function getPreviousHash(): ?string
    {
        return $this->previousHash;
    }

    public function getHash(): string
    {
        return $this->hash ?? $this->computeHash();
    }

    /**
     * Compute SHA-256 Merkle chain hash based on canonical representation.
     */
    public function computeHash(): string
    {
        $canonicalData = [
            'id' => $this->id,
            'sequence' => $this->sequence,
            'timestamp_ns' => $this->timestampNs,
            'type' => $this->type,
            'payload' => $this->canonicalize($this->payload),
            'metadata' => $this->canonicalize($this->metadata),
            'previous_hash' => $this->previousHash ?? 'GENESIS_ROOT'
        ];

        return hash('sha256', (string) json_encode($canonicalData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    private function canonicalize(mixed $data): mixed
    {
        if (!is_array($data)) {
            return $data;
        }

        $isAssoc = array_keys($data) !== range(0, count($data) - 1);
        if ($isAssoc) {
            ksort($data);
        }

        foreach ($data as $key => $value) {
            $data[$key] = $this->canonicalize($value);
        }

        return $data;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'sequence' => $this->sequence,
            'timestamp_ns' => $this->timestampNs,
            'timestamp' => $this->isoTimestamp,
            'type' => $this->type,
            'payload' => $this->payload,
            'metadata' => $this->metadata,
            'previous_hash' => $this->previousHash,
            'hash' => $this->getHash()
        ];
    }

    public static function fromArray(array $data): self
    {
        $event = new self(
            (int) ($data['sequence'] ?? 0),
            (string) ($data['type'] ?? 'unknown'),
            (array) ($data['payload'] ?? []),
            (array) ($data['metadata'] ?? []),
            isset($data['previous_hash']) ? (string)$data['previous_hash'] : null,
            isset($data['timestamp_ns']) ? (int)$data['timestamp_ns'] : null,
            isset($data['id']) ? (string)$data['id'] : null,
            isset($data['hash']) ? (string)$data['hash'] : null
        );

        if (isset($data['timestamp'])) {
            $event->isoTimestamp = (string) $data['timestamp'];
        }

        return $event;
    }
}
