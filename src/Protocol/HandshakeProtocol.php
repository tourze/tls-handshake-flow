<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Protocol;

/**
 * 握手协议实现类
 */
class HandshakeProtocol extends AbstractHandshakeProtocol
{
    public function processHandshakeMessage(string $message): ?string
    {
        // 这里只是一个基本实现，具体处理逻辑将在子类中实现
        return null;
    }
}
