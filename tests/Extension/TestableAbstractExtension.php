<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Extension;

use Tourze\TLSHandshakeFlow\Extension\AbstractExtension;

final class TestableAbstractExtension extends AbstractExtension
{
    /**
     * @return static
     */
    public static function decode(string $data): static
    {
        return new self();
    }

    public function getType(): int
    {
        return 0x0000;
    }

    public function encode(): string
    {
        return '';
    }

    public function testEncodeUint16(int $value): string
    {
        return $this->encodeUint16($value);
    }

    /**
     * @return array{value: int, offset: int}
     */
    public function testDecodeUint16(string $data, int $offset): array
    {
        $result = self::decodeUint16($data, $offset);

        return ['value' => $result->value, 'offset' => $result->newOffset];
    }
}
