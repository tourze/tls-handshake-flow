<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Protocol\AbstractHandshakeProtocol;
use Tourze\TLSHandshakeFlow\Protocol\HandshakeProtocolInterface;
use Tourze\TLSHandshakeFlow\Protocol\HandshakeProtocolState;

/**
 * @internal
 */
#[CoversClass(AbstractHandshakeProtocol::class)]
final class AbstractHandshakeProtocolTest extends TestCase
{
    private TestableAbstractHandshakeProtocol $protocol;

    protected function setUp(): void
    {
        parent::setUp();

        $this->protocol = new TestableAbstractHandshakeProtocol();
    }

    public function testImplementsHandshakeProtocolInterface(): void
    {
        $this->assertInstanceOf(HandshakeProtocolInterface::class, $this->protocol);
    }

    public function testInitialState(): void
    {
        $this->assertSame(HandshakeProtocolState::NOT_STARTED, $this->protocol->getState());
        $this->assertFalse($this->protocol->isHandshakeCompleted());
    }

    public function testStartHandshake(): void
    {
        $this->protocol->startHandshake();
        $this->assertSame(HandshakeProtocolState::IN_PROGRESS, $this->protocol->getState());
        $this->assertFalse($this->protocol->isHandshakeCompleted());
    }

    public function testCompleteHandshake(): void
    {
        $this->protocol->startHandshake();
        $this->protocol->completeHandshake();

        $this->assertSame(HandshakeProtocolState::COMPLETED, $this->protocol->getState());
        $this->assertTrue($this->protocol->isHandshakeCompleted());
    }

    public function testCompleteHandshakeWithoutStart(): void
    {
        $this->protocol->completeHandshake();

        $this->assertSame(HandshakeProtocolState::COMPLETED, $this->protocol->getState());
        $this->assertTrue($this->protocol->isHandshakeCompleted());
    }

    public function testVersionManagement(): void
    {
        $this->assertNull($this->protocol->getVersion());

        $this->protocol->setVersion('TLS 1.3');
        $this->assertSame('TLS 1.3', $this->protocol->getVersion());

        $this->protocol->setVersion('TLS 1.2');
        $this->assertSame('TLS 1.2', $this->protocol->getVersion());
    }

    public function testHandshakeWorkflow(): void
    {
        // Initial state
        $this->assertSame(HandshakeProtocolState::NOT_STARTED, $this->protocol->getState());
        $this->assertFalse($this->protocol->isHandshakeCompleted());

        // Start handshake
        $this->protocol->startHandshake();
        $this->assertSame(HandshakeProtocolState::IN_PROGRESS, $this->protocol->getState());
        $this->assertFalse($this->protocol->isHandshakeCompleted());

        // Set version during handshake
        $this->protocol->setVersion('TLS 1.3');
        $this->assertSame('TLS 1.3', $this->protocol->getVersion());

        // Complete handshake
        $this->protocol->completeHandshake();
        $this->assertSame(HandshakeProtocolState::COMPLETED, $this->protocol->getState());
        $this->assertTrue($this->protocol->isHandshakeCompleted());
    }
}
