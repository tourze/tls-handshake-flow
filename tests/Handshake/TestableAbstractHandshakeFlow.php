<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Handshake;

use Tourze\TLSHandshakeFlow\Handshake\AbstractHandshakeFlow;
use Tourze\TLSHandshakeFlow\Handshake\HandshakeStage;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

class TestableAbstractHandshakeFlow extends AbstractHandshakeFlow
{
    public function processMessage(string $messageData): void
    {
        // Test implementation
    }

    public function getNextExpectedMessage(): ?HandshakeMessageType
    {
        return HandshakeMessageType::CLIENT_HELLO;
    }

    public function getExpectedMessageTypes(HandshakeStage $stage): array
    {
        return [HandshakeMessageType::CLIENT_HELLO];
    }
}
