<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Extension\DecodeResult;

/**
 * @internal
 */
#[CoversClass(DecodeResult::class)]
final class DecodeResultTest extends TestCase
{
    public function testConstruct(): void
    {
        $result = new DecodeResult(0x1234, 10);

        $this->assertSame(0x1234, $result->value);
        $this->assertSame(10, $result->newOffset);
    }

    public function testReadonlyProperties(): void
    {
        $result = new DecodeResult(100, 20);

        // 验证属性是只读的
        $this->assertSame(100, $result->value);
        $this->assertSame(20, $result->newOffset);
    }
}
