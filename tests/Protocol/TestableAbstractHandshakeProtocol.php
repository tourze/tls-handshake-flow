<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\Protocol;

use Tourze\TLSHandshakeFlow\Protocol\AbstractHandshakeProtocol;

class TestableAbstractHandshakeProtocol extends AbstractHandshakeProtocol
{
    public function processHandshakeMessage(string $message): ?string
    {
        // Test implementation
        return 'test response';
    }

    public function generateHandshakeMessage(): string
    {
        return 'test message';
    }
}
