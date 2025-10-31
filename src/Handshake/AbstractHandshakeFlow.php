<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Handshake;

use Tourze\TLSHandshakeFlow\Exception\InvalidHandshakeDataException;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 握手流程抽象实现
 */
abstract class AbstractHandshakeFlow implements HandshakeFlowInterface
{
    /**
     * 当前握手阶段
     */
    protected HandshakeStage $currentStage = HandshakeStage::INITIAL;

    public function getCurrentStage(): HandshakeStage
    {
        return $this->currentStage;
    }

    public function advanceToStage(HandshakeStage $stage): void
    {
        if ($stage->value < $this->currentStage->value) {
            throw new InvalidHandshakeDataException('不能回退到先前的握手阶段');
        }

        $this->currentStage = $stage;
    }

    public function isStageCompleted(HandshakeStage $stage): bool
    {
        return $this->currentStage->value > $stage->value;
    }

    public function acceptsMessageType(HandshakeMessageType $messageType): bool
    {
        $expectedTypes = $this->getExpectedMessageTypes($this->currentStage);

        return in_array($messageType, $expectedTypes, true);
    }
}
