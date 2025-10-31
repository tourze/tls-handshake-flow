<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Handshake;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Exception\InvalidHandshakeDataException;
use Tourze\TLSHandshakeFlow\Handshake\AbstractHandshakeFlow;
use Tourze\TLSHandshakeFlow\Handshake\HandshakeFlowInterface;
use Tourze\TLSHandshakeFlow\Handshake\HandshakeStage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * @internal
 */
#[CoversClass(AbstractHandshakeFlow::class)]
final class AbstractHandshakeFlowTest extends TestCase
{
    private TestableAbstractHandshakeFlow $flow;

    protected function setUp(): void
    {
        parent::setUp();

        $this->flow = new TestableAbstractHandshakeFlow();
    }

    public function testImplementsHandshakeFlowInterface(): void
    {
        $this->assertInstanceOf(HandshakeFlowInterface::class, $this->flow);
    }

    public function testInitialStage(): void
    {
        $this->assertSame(HandshakeStage::INITIAL, $this->flow->getCurrentStage());
    }

    public function testAdvanceToStage(): void
    {
        $this->flow->advanceToStage(HandshakeStage::NEGOTIATING);
        $this->assertSame(HandshakeStage::NEGOTIATING, $this->flow->getCurrentStage());

        $this->flow->advanceToStage(HandshakeStage::KEY_EXCHANGE);
        $this->assertSame(HandshakeStage::KEY_EXCHANGE, $this->flow->getCurrentStage());
    }

    public function testCannotAdvanceToEarlierStage(): void
    {
        $this->flow->advanceToStage(HandshakeStage::KEY_EXCHANGE);

        $this->expectException(InvalidHandshakeDataException::class);
        $this->expectExceptionMessage('不能回退到先前的握手阶段');

        $this->flow->advanceToStage(HandshakeStage::NEGOTIATING);
    }

    public function testCanAdvanceToSameStage(): void
    {
        $this->flow->advanceToStage(HandshakeStage::NEGOTIATING);
        $this->flow->advanceToStage(HandshakeStage::NEGOTIATING);

        $this->assertSame(HandshakeStage::NEGOTIATING, $this->flow->getCurrentStage());
    }

    public function testIsStageCompleted(): void
    {
        $this->assertFalse($this->flow->isStageCompleted(HandshakeStage::INITIAL));
        $this->assertFalse($this->flow->isStageCompleted(HandshakeStage::NEGOTIATING));

        $this->flow->advanceToStage(HandshakeStage::KEY_EXCHANGE);

        $this->assertTrue($this->flow->isStageCompleted(HandshakeStage::INITIAL));
        $this->assertTrue($this->flow->isStageCompleted(HandshakeStage::NEGOTIATING));
        $this->assertFalse($this->flow->isStageCompleted(HandshakeStage::KEY_EXCHANGE));
        $this->assertFalse($this->flow->isStageCompleted(HandshakeStage::AUTHENTICATION));
    }

    public function testAcceptsMessageType(): void
    {
        $messageType = HandshakeMessageType::CLIENT_HELLO;
        $result = $this->flow->acceptsMessageType($messageType);

        $this->assertTrue($result);
    }
}
