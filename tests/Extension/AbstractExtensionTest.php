<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Extension\AbstractExtension;
use Tourze\TLSHandshakeFlow\Extension\ExtensionInterface;

/**
 * @internal
 */
#[CoversClass(AbstractExtension::class)]
final class AbstractExtensionTest extends TestCase
{
    private TestableAbstractExtension $extension;

    protected function setUp(): void
    {
        parent::setUp();

        $this->extension = new TestableAbstractExtension();
    }

    public function testImplementsExtensionInterface(): void
    {
        $this->assertInstanceOf(ExtensionInterface::class, $this->extension);
    }

    public function testEncodeUint16(): void
    {
        $result = $this->extension->testEncodeUint16(0x1234);
        $this->assertSame("\x12\x34", $result);
    }

    public function testDecodeUint16(): void
    {
        $data = "\x12\x34\x56\x78";
        $offset = 0;
        $result = $this->extension->testDecodeUint16($data, $offset);
        $this->assertSame(0x1234, $result['value']);
        $this->assertSame(2, $result['offset']);
    }

    public function testIsApplicableForVersionDefaultTrue(): void
    {
        $this->assertTrue($this->extension->isApplicableForVersion('1.2'));
        $this->assertTrue($this->extension->isApplicableForVersion('1.3'));
        $this->assertTrue($this->extension->isApplicableForVersion('1.0'));
    }
}
