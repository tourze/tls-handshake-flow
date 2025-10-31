<?php

namespace Tourze\TLSHandshakeFlow\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Protocol\HandshakeProtocol;
use Tourze\TLSHandshakeFlow\Protocol\HandshakeProtocolInterface;
use Tourze\TLSHandshakeFlow\Protocol\HandshakeProtocolState;

/**
 * @internal
 */
#[CoversClass(HandshakeProtocol::class)]
final class HandshakeProtocolTest extends TestCase
{
    /**
     * 测试接口实现
     */
    public function testInterfaceImplementation(): void
    {
        $protocol = new HandshakeProtocol();
        $this->assertInstanceOf(HandshakeProtocolInterface::class, $protocol);
    }

    /**
     * 测试握手状态是否按预期变更
     */
    public function testHandshakeStateTransition(): void
    {
        $protocol = new HandshakeProtocol();

        // 握手初始状态为NOT_STARTED
        $this->assertEquals(HandshakeProtocolState::NOT_STARTED, $protocol->getState());

        // 开始握手
        $protocol->startHandshake();
        $this->assertEquals(HandshakeProtocolState::IN_PROGRESS, $protocol->getState());

        // 完成握手
        $protocol->completeHandshake();
        $this->assertEquals(HandshakeProtocolState::COMPLETED, $protocol->getState());
    }

    /**
     * 测试获取和设置版本
     */
    public function testVersionHandling(): void
    {
        $protocol = new HandshakeProtocol();

        // 默认版本
        $this->assertNull($protocol->getVersion());

        // 设置版本
        $protocol->setVersion('TLS 1.2');
        $this->assertEquals('TLS 1.2', $protocol->getVersion());
    }

    /**
     * 测试处理握手消息
     */
    public function testProcessHandshakeMessage(): void
    {
        $protocol = new HandshakeProtocol();

        // 测试空消息处理
        $result = $protocol->processHandshakeMessage('');
        $this->assertNull($result);

        // 测试非空消息处理
        $result = $protocol->processHandshakeMessage('test_message');
        $this->assertNull($result);

        // 测试二进制消息处理
        $binaryMessage = "\x01\x02\x03\x04";
        $result = $protocol->processHandshakeMessage($binaryMessage);
        $this->assertNull($result);
    }
}
