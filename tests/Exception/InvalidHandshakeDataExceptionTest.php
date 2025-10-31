<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSHandshakeFlow\Exception\InvalidHandshakeDataException;

/**
 * @internal
 */
#[CoversClass(InvalidHandshakeDataException::class)]
final class InvalidHandshakeDataExceptionTest extends AbstractExceptionTestCase
{
    public function testExceptionExtends(): void
    {
        $exception = new InvalidHandshakeDataException('Test message');
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function testExceptionMessage(): void
    {
        $message = 'Invalid handshake data';
        $exception = new InvalidHandshakeDataException($message);
        $this->assertSame($message, $exception->getMessage());
    }

    public function testExceptionCode(): void
    {
        $code = 123;
        $exception = new InvalidHandshakeDataException('Test message', $code);
        $this->assertSame($code, $exception->getCode());
    }
}
