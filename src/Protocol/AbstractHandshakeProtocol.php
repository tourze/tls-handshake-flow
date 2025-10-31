<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Protocol;

/**
 * 握手协议抽象基类
 */
abstract class AbstractHandshakeProtocol implements HandshakeProtocolInterface
{
    /**
     * 当前握手状态
     */
    protected HandshakeProtocolState $state = HandshakeProtocolState::NOT_STARTED;

    /**
     * TLS协议版本
     */
    protected ?string $version = null;

    public function startHandshake(): void
    {
        $this->state = HandshakeProtocolState::IN_PROGRESS;
    }

    public function getState(): HandshakeProtocolState
    {
        return $this->state;
    }

    public function isHandshakeCompleted(): bool
    {
        return HandshakeProtocolState::COMPLETED === $this->state;
    }

    public function completeHandshake(): void
    {
        $this->state = HandshakeProtocolState::COMPLETED;
    }

    public function getVersion(): ?string
    {
        return $this->version;
    }

    public function setVersion(string $version): void
    {
        $this->version = $version;
    }
}
