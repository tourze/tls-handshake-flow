<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Extension\ExtensionType;
use Tourze\TLSHandshakeFlow\Extension\PostHandshakeAuthExtension;

/**
 * @internal
 */
#[CoversClass(PostHandshakeAuthExtension::class)]
final class PostHandshakeAuthExtensionTest extends TestCase
{
    private PostHandshakeAuthExtension $extension;

    protected function setUp(): void
    {
        parent::setUp();

        $this->extension = new PostHandshakeAuthExtension();
    }

    public function testGetType(): void
    {
        $this->assertSame(ExtensionType::POST_HANDSHAKE_AUTH->value, $this->extension->getType());
    }

    public function testEncode(): void
    {
        $encoded = $this->extension->encode();
        $this->assertSame('', $encoded);
    }

    public function testDecode(): void
    {
        $extension = PostHandshakeAuthExtension::decode('');
        $this->assertInstanceOf(PostHandshakeAuthExtension::class, $extension);
    }

    public function testIsApplicableForVersion(): void
    {
        $this->assertTrue($this->extension->isApplicableForVersion('1.3'));
        $this->assertFalse($this->extension->isApplicableForVersion('1.2'));
        $this->assertFalse($this->extension->isApplicableForVersion('1.1'));
    }
}
