<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeFlow\Protocol\TLSVersion;

/**
 * @internal
 */
#[CoversClass(TLSVersion::class)]
final class TLSVersionTest extends AbstractEnumTestCase
{
    public function testImplementsInterfaces(): void
    {
        $this->assertInstanceOf(Itemable::class, TLSVersion::TLS_1_2);
        $this->assertInstanceOf(Labelable::class, TLSVersion::TLS_1_2);
        $this->assertInstanceOf(Selectable::class, TLSVersion::TLS_1_2);
    }

    public function testEnumValues(): void
    {
        $this->assertSame(0x0300, TLSVersion::SSL_3_0->value);
        $this->assertSame(0x0301, TLSVersion::TLS_1_0->value);
        $this->assertSame(0x0302, TLSVersion::TLS_1_1->value);
        $this->assertSame(0x0303, TLSVersion::TLS_1_2->value);
        $this->assertSame(0x0304, TLSVersion::TLS_1_3->value);
    }

    public function testGetName(): void
    {
        $this->assertSame('SSL 3.0', TLSVersion::SSL_3_0->getName());
        $this->assertSame('TLS 1.0', TLSVersion::TLS_1_0->getName());
        $this->assertSame('TLS 1.1', TLSVersion::TLS_1_1->getName());
        $this->assertSame('TLS 1.2', TLSVersion::TLS_1_2->getName());
        $this->assertSame('TLS 1.3', TLSVersion::TLS_1_3->getName());
    }

    public function testGetLabel(): void
    {
        $this->assertSame('SSL 3.0', TLSVersion::SSL_3_0->getLabel());
        $this->assertSame('TLS 1.0', TLSVersion::TLS_1_0->getLabel());
        $this->assertSame('TLS 1.1', TLSVersion::TLS_1_1->getLabel());
        $this->assertSame('TLS 1.2', TLSVersion::TLS_1_2->getLabel());
        $this->assertSame('TLS 1.3', TLSVersion::TLS_1_3->getLabel());
    }

    public function testIsSecure(): void
    {
        $this->assertFalse(TLSVersion::SSL_3_0->isSecure());
        $this->assertFalse(TLSVersion::TLS_1_0->isSecure());
        $this->assertFalse(TLSVersion::TLS_1_1->isSecure());
        $this->assertTrue(TLSVersion::TLS_1_2->isSecure());
        $this->assertTrue(TLSVersion::TLS_1_3->isSecure());
    }

    public function testGetVersionName(): void
    {
        $this->assertSame('SSL 3.0', TLSVersion::getVersionName(0x0300));
        $this->assertSame('TLS 1.0', TLSVersion::getVersionName(0x0301));
        $this->assertSame('TLS 1.2', TLSVersion::getVersionName(0x0303));
        $this->assertSame('TLS 1.3', TLSVersion::getVersionName(0x0304));
        $this->assertSame('Unknown (0x9999)', TLSVersion::getVersionName(0x9999));
    }

    public function testGetRecommendedVersions(): void
    {
        $recommended = TLSVersion::getRecommendedVersions();

        $this->assertCount(2, $recommended);
        $this->assertSame(TLSVersion::TLS_1_3, $recommended[0]);
        $this->assertSame(TLSVersion::TLS_1_2, $recommended[1]);
    }

    public function testAllRecommendedVersionsAreSecure(): void
    {
        $recommended = TLSVersion::getRecommendedVersions();

        foreach ($recommended as $version) {
            $this->assertTrue($version->isSecure(), "Recommended version {$version->getName()} should be secure");
        }
    }

    public function testFromValue(): void
    {
        $this->assertSame(TLSVersion::SSL_3_0, TLSVersion::from(0x0300));
        $this->assertSame(TLSVersion::TLS_1_2, TLSVersion::from(0x0303));
        $this->assertSame(TLSVersion::TLS_1_3, TLSVersion::from(0x0304));
    }

    public function testTryFromValue(): void
    {
        $this->assertSame(TLSVersion::TLS_1_2, TLSVersion::tryFrom(0x0303));
        $this->assertNull(TLSVersion::tryFrom(0x9999));
    }

    public function testVersionProgression(): void
    {
        $versions = [
            TLSVersion::SSL_3_0,
            TLSVersion::TLS_1_0,
            TLSVersion::TLS_1_1,
            TLSVersion::TLS_1_2,
            TLSVersion::TLS_1_3,
        ];

        for ($i = 0; $i < count($versions) - 1; ++$i) {
            $this->assertLessThan(
                $versions[$i + 1]->value,
                $versions[$i]->value,
                "Version {$versions[$i]->getName()} should have a lower value than {$versions[$i + 1]->getName()}"
            );
        }
    }

    public function testToArray(): void
    {
        $version = TLSVersion::TLS_1_2;
        $result = $version->toArray();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('value', $result);
        $this->assertArrayHasKey('label', $result);
        $this->assertCount(2, $result);

        $this->assertEquals($version->value, $result['value']);
        $this->assertEquals($version->getLabel(), $result['label']);

        // 测试不同版本
        $tls13 = TLSVersion::TLS_1_3;
        $tls13Result = $tls13->toArray();

        $this->assertEquals(0x0304, $tls13Result['value']);
        $this->assertEquals('TLS 1.3', $tls13Result['label']);

        // 测试SSL版本
        $ssl30 = TLSVersion::SSL_3_0;
        $ssl30Result = $ssl30->toArray();

        $this->assertEquals(0x0300, $ssl30Result['value']);
        $this->assertEquals('SSL 3.0', $ssl30Result['label']);
    }
}
