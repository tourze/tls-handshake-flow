<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Handshake;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeFlow\Handshake\HandshakeStage;

/**
 * @internal
 */
#[CoversClass(HandshakeStage::class)]
final class HandshakeStageTest extends AbstractEnumTestCase
{
    public function testImplementsInterfaces(): void
    {
        $this->assertInstanceOf(Itemable::class, HandshakeStage::INITIAL);
        $this->assertInstanceOf(Labelable::class, HandshakeStage::INITIAL);
        $this->assertInstanceOf(Selectable::class, HandshakeStage::INITIAL);
    }

    public function testEnumValues(): void
    {
        $this->assertSame(1, HandshakeStage::INITIAL->value);
        $this->assertSame(2, HandshakeStage::NEGOTIATING->value);
        $this->assertSame(3, HandshakeStage::KEY_EXCHANGE->value);
        $this->assertSame(4, HandshakeStage::AUTHENTICATION->value);
        $this->assertSame(5, HandshakeStage::FINISHED->value);
    }

    public function testGetLabel(): void
    {
        $this->assertSame('初始阶段', HandshakeStage::INITIAL->getLabel());
        $this->assertSame('协商阶段', HandshakeStage::NEGOTIATING->getLabel());
        $this->assertSame('密钥交换阶段', HandshakeStage::KEY_EXCHANGE->getLabel());
        $this->assertSame('认证阶段', HandshakeStage::AUTHENTICATION->getLabel());
        $this->assertSame('完成阶段', HandshakeStage::FINISHED->getLabel());
    }

    public function testAllCasesHaveLabels(): void
    {
        foreach (HandshakeStage::cases() as $case) {
            $this->assertNotEmpty($case->getLabel(), "Handshake stage {$case->name} should have a label");
        }
    }

    public function testFromValue(): void
    {
        $this->assertSame(HandshakeStage::INITIAL, HandshakeStage::from(1));
        $this->assertSame(HandshakeStage::NEGOTIATING, HandshakeStage::from(2));
        $this->assertSame(HandshakeStage::KEY_EXCHANGE, HandshakeStage::from(3));
        $this->assertSame(HandshakeStage::AUTHENTICATION, HandshakeStage::from(4));
        $this->assertSame(HandshakeStage::FINISHED, HandshakeStage::from(5));
    }

    public function testTryFromValue(): void
    {
        $this->assertSame(HandshakeStage::INITIAL, HandshakeStage::tryFrom(1));
        $this->assertNull(HandshakeStage::tryFrom(99));
    }

    public function testStageProgression(): void
    {
        $stages = [
            HandshakeStage::INITIAL,
            HandshakeStage::NEGOTIATING,
            HandshakeStage::KEY_EXCHANGE,
            HandshakeStage::AUTHENTICATION,
            HandshakeStage::FINISHED,
        ];

        for ($i = 0; $i < count($stages) - 1; ++$i) {
            $this->assertLessThan(
                $stages[$i + 1]->value,
                $stages[$i]->value,
                "Stage {$stages[$i]->name} should have a lower value than {$stages[$i + 1]->name}"
            );
        }
    }

    public function testToArray(): void
    {
        $stage = HandshakeStage::INITIAL;
        $result = $stage->toArray();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('value', $result);
        $this->assertArrayHasKey('label', $result);
        $this->assertCount(2, $result);

        $this->assertEquals($stage->value, $result['value']);
        $this->assertEquals($stage->getLabel(), $result['label']);

        // 测试不同阶段
        $negotiating = HandshakeStage::NEGOTIATING;
        $negotiatingResult = $negotiating->toArray();

        $this->assertEquals(2, $negotiatingResult['value']);
        $this->assertEquals('协商阶段', $negotiatingResult['label']);

        // 测试最终阶段
        $finished = HandshakeStage::FINISHED;
        $finishedResult = $finished->toArray();

        $this->assertEquals(5, $finishedResult['value']);
        $this->assertEquals('完成阶段', $finishedResult['label']);
    }
}
