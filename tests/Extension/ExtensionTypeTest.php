<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeFlow\Extension\ExtensionType;

/**
 * @internal
 */
#[CoversClass(ExtensionType::class)]
final class ExtensionTypeTest extends AbstractEnumTestCase
{
    public function testImplementsInterfaces(): void
    {
        $this->assertInstanceOf(Itemable::class, ExtensionType::SERVER_NAME);
        $this->assertInstanceOf(Labelable::class, ExtensionType::SERVER_NAME);
        $this->assertInstanceOf(Selectable::class, ExtensionType::SERVER_NAME);
    }

    public function testEnumValues(): void
    {
        $this->assertSame(0x0000, ExtensionType::SERVER_NAME->value);
        $this->assertSame(0x0001, ExtensionType::MAX_FRAGMENT_LENGTH->value);
        $this->assertSame(0x00FF, ExtensionType::RENEGOTIATION_INFO->value);
        $this->assertSame(0x0029, ExtensionType::PRE_SHARED_KEY->value);
        $this->assertSame(0x0031, ExtensionType::POST_HANDSHAKE_AUTH->value);
        $this->assertSame(0x0033, ExtensionType::KEY_SHARE->value);
    }

    public function testGetLabel(): void
    {
        $this->assertSame('服务器名称指示', ExtensionType::SERVER_NAME->getLabel());
        $this->assertSame('安全重协商信息', ExtensionType::RENEGOTIATION_INFO->getLabel());
        $this->assertSame('预共享密钥', ExtensionType::PRE_SHARED_KEY->getLabel());
        $this->assertSame('后握手认证', ExtensionType::POST_HANDSHAKE_AUTH->getLabel());
        $this->assertSame('密钥共享', ExtensionType::KEY_SHARE->getLabel());
    }

    public function testAllCasesHaveLabels(): void
    {
        foreach (ExtensionType::cases() as $case) {
            $this->assertNotEmpty($case->getLabel(), "Extension type {$case->name} should have a label");
        }
    }

    public function testFromValue(): void
    {
        $this->assertSame(ExtensionType::SERVER_NAME, ExtensionType::from(0x0000));
        $this->assertSame(ExtensionType::RENEGOTIATION_INFO, ExtensionType::from(0x00FF));
        $this->assertSame(ExtensionType::PRE_SHARED_KEY, ExtensionType::from(0x0029));
    }

    public function testTryFromValue(): void
    {
        $this->assertSame(ExtensionType::SERVER_NAME, ExtensionType::tryFrom(0x0000));
        $this->assertNull(ExtensionType::tryFrom(0x9999));
    }

    public function testToArray(): void
    {
        $extensionType = ExtensionType::SERVER_NAME;
        $result = $extensionType->toArray();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('value', $result);
        $this->assertArrayHasKey('label', $result);
        $this->assertCount(2, $result);

        $this->assertEquals($extensionType->value, $result['value']);
        $this->assertEquals($extensionType->getLabel(), $result['label']);

        // 测试不同的扩展类型
        $renegotiation = ExtensionType::RENEGOTIATION_INFO;
        $renegotiationResult = $renegotiation->toArray();

        $this->assertEquals(0x00FF, $renegotiationResult['value']);
        $this->assertEquals('安全重协商信息', $renegotiationResult['label']);

        // 测试TLS 1.3扩展
        $preSharedKey = ExtensionType::PRE_SHARED_KEY;
        $pskResult = $preSharedKey->toArray();

        $this->assertEquals(0x0029, $pskResult['value']);
        $this->assertEquals('预共享密钥', $pskResult['label']);
    }
}
