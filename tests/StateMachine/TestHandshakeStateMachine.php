<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use Tourze\TLSHandshakeFlow\StateMachine\AbstractHandshakeStateMachine;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

class TestHandshakeStateMachine extends AbstractHandshakeStateMachine
{
    public function getNextState(HandshakeMessageType $messageType): HandshakeStateEnum
    {
        return $this->stateTransitions[$this->currentState->value][$messageType->value] ?? HandshakeStateEnum::ERROR;
    }

    protected function initializeStateTransitions(): void
    {
        $this->stateTransitions[HandshakeStateEnum::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_SERVER_HELLO,
        ];
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO->value] = [
            HandshakeMessageType::SERVER_HELLO->value => HandshakeStateEnum::WAIT_CERTIFICATE,
        ];
    }
}
