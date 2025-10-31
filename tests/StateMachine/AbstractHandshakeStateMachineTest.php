<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Exception\InvalidHandshakeDataException;
use Tourze\TLSHandshakeFlow\StateMachine\AbstractHandshakeStateMachine;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateMachineInterface;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * @internal
 */
#[CoversClass(AbstractHandshakeStateMachine::class)]
final class AbstractHandshakeStateMachineTest extends TestCase
{
    private TestableAbstractHandshakeStateMachine $stateMachine;

    protected function setUp(): void
    {
        parent::setUp();

        $this->stateMachine = new TestableAbstractHandshakeStateMachine();
    }

    public function testImplementsHandshakeStateMachineInterface(): void
    {
        $this->assertInstanceOf(HandshakeStateMachineInterface::class, $this->stateMachine);
    }

    public function testInitialState(): void
    {
        $this->assertSame(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    public function testTransitionToValidState(): void
    {
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_SERVER_HELLO);
        $this->assertSame(HandshakeStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getCurrentState());
    }

    public function testTransitionToInvalidState(): void
    {
        $this->expectException(InvalidHandshakeDataException::class);
        $this->expectExceptionMessage('无效的状态');

        // Create a new state machine with restricted valid states
        $restrictedStateMachine = new class extends AbstractHandshakeStateMachine {
            protected function initializeValidStates(): void
            {
                $this->validStates = [HandshakeStateEnum::INITIAL];
            }

            protected function initializeStateTransitions(): void
            {
                // Empty implementation
            }
        };

        $restrictedStateMachine->transitionTo(HandshakeStateEnum::WAIT_SERVER_HELLO);
    }

    public function testGetNextStateWithDefinedTransition(): void
    {
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertSame(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
    }

    public function testGetNextStateWithUndefinedTransition(): void
    {
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO_DONE);
        $this->assertSame(HandshakeStateEnum::ERROR, $nextState);
    }

    public function testIsInErrorState(): void
    {
        $this->assertFalse($this->stateMachine->isInErrorState());

        $this->stateMachine->transitionTo(HandshakeStateEnum::ERROR);
        $this->assertTrue($this->stateMachine->isInErrorState());
    }

    public function testIsHandshakeCompleted(): void
    {
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());

        $this->stateMachine->transitionTo(HandshakeStateEnum::CONNECTED);
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    public function testReset(): void
    {
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_SERVER_HELLO);
        $this->assertSame(HandshakeStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getCurrentState());

        $this->stateMachine->reset();
        $this->assertSame(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
    }

    public function testValidStatesInitialization(): void
    {
        $validStates = $this->stateMachine->getValidStates();

        $expectedStates = [
            HandshakeStateEnum::INITIAL,
            HandshakeStateEnum::WAIT_SERVER_HELLO,
            HandshakeStateEnum::WAIT_CERTIFICATE,
            HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE,
            HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT,
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
            HandshakeStateEnum::WAIT_FINISHED,
            HandshakeStateEnum::WAIT_CLIENT_FINISHED,
            HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
            HandshakeStateEnum::PROCESS_EARLY_DATA,
            HandshakeStateEnum::WAIT_CLIENT_VERIFY,
            HandshakeStateEnum::CONNECTED,
            HandshakeStateEnum::ERROR,
        ];

        $this->assertCount(count($expectedStates), $validStates);

        foreach ($expectedStates as $expectedState) {
            $this->assertContains($expectedState, $validStates, "Valid states should contain {$expectedState->value}");
        }
    }
}
