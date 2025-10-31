<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Exception\InvalidHandshakeDataException;
use Tourze\TLSHandshakeFlow\Extension\ExtensionType;
use Tourze\TLSHandshakeFlow\Extension\RenegotiationInfoExtension;

/**
 * @internal
 */
#[CoversClass(RenegotiationInfoExtension::class)]
final class RenegotiationInfoExtensionTest extends TestCase
{
    private RenegotiationInfoExtension $extension;

    protected function setUp(): void
    {
        parent::setUp();

        $this->extension = new RenegotiationInfoExtension();
    }

    public function testGetType(): void
    {
        $this->assertSame(ExtensionType::RENEGOTIATION_INFO->value, $this->extension->getType());
    }

    public function testSetAndGetRenegotiatedConnection(): void
    {
        $data = 'test_connection_data';
        $this->extension->setRenegotiatedConnection($data);
        $this->assertSame($data, $this->extension->getRenegotiatedConnection());
    }

    public function testEncodeEmptyData(): void
    {
        $encoded = $this->extension->encode();
        $this->assertSame("\x00", $encoded);
    }

    public function testEncodeWithData(): void
    {
        $data = 'test';
        $this->extension->setRenegotiatedConnection($data);
        $encoded = $this->extension->encode();
        $this->assertSame("\x04test", $encoded);
    }

    public function testDecodeEmptyData(): void
    {
        $extension = RenegotiationInfoExtension::decode("\x00");
        $this->assertSame('', $extension->getRenegotiatedConnection());
    }

    public function testDecodeWithData(): void
    {
        $extension = RenegotiationInfoExtension::decode("\x04test");
        $this->assertSame('test', $extension->getRenegotiatedConnection());
    }

    public function testDecodeWithInvalidDataThrowsException(): void
    {
        $this->expectException(InvalidHandshakeDataException::class);
        $this->expectExceptionMessage('安全重协商扩展数据不完整');
        RenegotiationInfoExtension::decode('');
    }

    public function testDecodeWithIncorrectLengthThrowsException(): void
    {
        $this->expectException(InvalidHandshakeDataException::class);
        $this->expectExceptionMessage('安全重协商扩展数据长度与实际不符');
        RenegotiationInfoExtension::decode("\x10test");
    }
}
