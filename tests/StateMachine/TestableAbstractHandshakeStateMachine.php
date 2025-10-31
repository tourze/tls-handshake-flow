<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use Tourze\TLSHandshakeFlow\StateMachine\AbstractHandshakeStateMachine;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

class TestableAbstractHandshakeStateMachine extends AbstractHandshakeStateMachine
{
    /**
     * @return array<int, HandshakeStateEnum>
     */
    public function getValidStates(): array
    {
        return $this->validStates;
    }

    protected function initializeStateTransitions(): void
    {
        $this->stateTransitions = [
            HandshakeStateEnum::INITIAL->value => [
                HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_SERVER_HELLO,
            ],
        ];
    }
}
