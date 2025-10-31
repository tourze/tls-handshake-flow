<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeFlow\Protocol\HandshakeProtocolState;

/**
 * @internal
 */
#[CoversClass(HandshakeProtocolState::class)]
final class HandshakeProtocolStateTest extends AbstractEnumTestCase
{
    public function testImplementsInterfaces(): void
    {
        $this->assertInstanceOf(Itemable::class, HandshakeProtocolState::NOT_STARTED);
        $this->assertInstanceOf(Labelable::class, HandshakeProtocolState::NOT_STARTED);
        $this->assertInstanceOf(Selectable::class, HandshakeProtocolState::NOT_STARTED);
    }

    public function testEnumValues(): void
    {
        $this->assertSame(0, HandshakeProtocolState::NOT_STARTED->value);
        $this->assertSame(1, HandshakeProtocolState::IN_PROGRESS->value);
        $this->assertSame(2, HandshakeProtocolState::COMPLETED->value);
        $this->assertSame(3, HandshakeProtocolState::FAILED->value);
    }

    public function testGetLabel(): void
    {
        $this->assertSame('未开始', HandshakeProtocolState::NOT_STARTED->getLabel());
        $this->assertSame('进行中', HandshakeProtocolState::IN_PROGRESS->getLabel());
        $this->assertSame('已完成', HandshakeProtocolState::COMPLETED->getLabel());
        $this->assertSame('失败', HandshakeProtocolState::FAILED->getLabel());
    }

    public function testAllCasesHaveLabels(): void
    {
        foreach (HandshakeProtocolState::cases() as $case) {
            $this->assertNotEmpty($case->getLabel(), "Handshake protocol state {$case->name} should have a label");
        }
    }

    public function testFromValue(): void
    {
        $this->assertSame(HandshakeProtocolState::NOT_STARTED, HandshakeProtocolState::from(0));
        $this->assertSame(HandshakeProtocolState::IN_PROGRESS, HandshakeProtocolState::from(1));
        $this->assertSame(HandshakeProtocolState::COMPLETED, HandshakeProtocolState::from(2));
        $this->assertSame(HandshakeProtocolState::FAILED, HandshakeProtocolState::from(3));
    }

    public function testTryFromValue(): void
    {
        $this->assertSame(HandshakeProtocolState::NOT_STARTED, HandshakeProtocolState::tryFrom(0));
        $this->assertNull(HandshakeProtocolState::tryFrom(99));
    }

    public function testStateProgression(): void
    {
        $orderedStates = [
            HandshakeProtocolState::NOT_STARTED,
            HandshakeProtocolState::IN_PROGRESS,
            HandshakeProtocolState::COMPLETED,
            HandshakeProtocolState::FAILED,
        ];

        for ($i = 0; $i < count($orderedStates) - 1; ++$i) {
            $this->assertLessThan(
                $orderedStates[$i + 1]->value,
                $orderedStates[$i]->value,
                "State {$orderedStates[$i]->name} should have a lower value than {$orderedStates[$i + 1]->name} (except FAILED which is terminal)"
            );
        }
    }

    public function testStateChecking(): void
    {
        $this->assertSame(0, HandshakeProtocolState::NOT_STARTED->value);
        $this->assertGreaterThan(HandshakeProtocolState::NOT_STARTED->value, HandshakeProtocolState::IN_PROGRESS->value);
        $this->assertGreaterThan(HandshakeProtocolState::IN_PROGRESS->value, HandshakeProtocolState::COMPLETED->value);
        $this->assertGreaterThan(HandshakeProtocolState::COMPLETED->value, HandshakeProtocolState::FAILED->value);
    }

    public function testToArray(): void
    {
        $state = HandshakeProtocolState::NOT_STARTED;
        $result = $state->toArray();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('value', $result);
        $this->assertArrayHasKey('label', $result);
        $this->assertCount(2, $result);

        $this->assertEquals($state->value, $result['value']);
        $this->assertEquals($state->getLabel(), $result['label']);

        // 测试进行中状态
        $inProgress = HandshakeProtocolState::IN_PROGRESS;
        $inProgressResult = $inProgress->toArray();

        $this->assertEquals(1, $inProgressResult['value']);
        $this->assertEquals('进行中', $inProgressResult['label']);

        // 测试完成状态
        $completed = HandshakeProtocolState::COMPLETED;
        $completedResult = $completed->toArray();

        $this->assertEquals(2, $completedResult['value']);
        $this->assertEquals('已完成', $completedResult['label']);
    }
}
