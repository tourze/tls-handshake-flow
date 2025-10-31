<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\StateMachine\ClientStateMachine;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;

/**
 * @internal
 */
#[CoversClass(ClientStateMachine::class)]
final class ClientStateMachineTest extends TestCase
{
    private ClientStateMachine $stateMachine;

    protected function setUp(): void
    {
        parent::setUp();

        $this->stateMachine = new ClientStateMachine();
    }

    public function testInitialState(): void
    {
        $this->assertSame(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
    }

    public function testTransitionToValidState(): void
    {
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_SERVER_HELLO);
        $this->assertSame(HandshakeStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getCurrentState());
    }

    public function testReset(): void
    {
        $this->stateMachine->transitionTo(HandshakeStateEnum::CONNECTED);
        $this->stateMachine->reset();
        $this->assertSame(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
    }

    public function testIsHandshakeCompleted(): void
    {
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());

        $this->stateMachine->transitionTo(HandshakeStateEnum::CONNECTED);
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    public function testIsInErrorState(): void
    {
        $this->assertFalse($this->stateMachine->isInErrorState());

        $this->stateMachine->transitionTo(HandshakeStateEnum::ERROR);
        $this->assertTrue($this->stateMachine->isInErrorState());
    }
}
