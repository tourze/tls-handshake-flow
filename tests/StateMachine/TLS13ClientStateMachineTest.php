<?php

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshakeFlow\StateMachine\TLS13ClientStateMachine;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * @internal
 */
#[CoversClass(TLS13ClientStateMachine::class)]
final class TLS13ClientStateMachineTest extends TestCase
{
    private TLS13ClientStateMachine $stateMachine;

    /**
     * 设置测试用例
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->stateMachine = new TLS13ClientStateMachine();
    }

    /**
     * 测试初始化状态
     */
    public function testInitialState(): void
    {
        $this->assertEquals(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    /**
     * 测试完整的TLS 1.3握手流程（不包含0-RTT）
     */
    public function testCompleteTLS13Handshake(): void
    {
        // 初始状态 -> WAIT_SERVER_HELLO (发送CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS (接收SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_CERTIFICATE (接收ENCRYPTED_EXTENSIONS)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE -> WAIT_CERTIFICATE_VERIFY (接收CERTIFICATE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE_VERIFY -> WAIT_FINISHED (接收CERTIFICATE_VERIFY)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_FINISHED -> WAIT_NEW_SESSION_TICKET (接收FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_NEW_SESSION_TICKET -> CONNECTED (接收NEW_SESSION_TICKET)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::NEW_SESSION_TICKET);
        $this->assertEquals(HandshakeStateEnum::CONNECTED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 确认握手已完成
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    /**
     * 测试不需要客户端证书的流程
     */
    public function testHandshakeWithoutClientCertificate(): void
    {
        // 跳到等待加密扩展状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS);

        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_CERTIFICATE (接收ENCRYPTED_EXTENSIONS)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 直接跳到WAIT_FINISHED(不需要客户端证书，服务器可能跳过证书消息)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);
    }

    /**
     * 测试PSK恢复模式
     */
    public function testPSKResumeHandshake(): void
    {
        // 初始状态 -> WAIT_SERVER_HELLO (发送带PSK的CLIENT_HELLO)
        $this->stateMachine->setPSKMode(true);
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS (接收SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // PSK模式下，服务器可能直接跳到FINISHED，不需要证书
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_FINISHED -> WAIT_NEW_SESSION_TICKET (接收FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);
    }

    /**
     * 测试错误处理
     */
    public function testErrorHandling(): void
    {
        // 初始状态下接收未预期的消息
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::ERROR, $nextState);
        $this->stateMachine->transitionTo($nextState);
        $this->assertTrue($this->stateMachine->isInErrorState());
    }

    /**
     * 测试是否可以跳过状态
     */
    public function testCanSkipState(): void
    {
        // 非PSK模式下，不能跳过任何状态
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE));
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY));
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::INITIAL));

        // PSK模式下，测试可以跳过的状态
        $this->stateMachine->setPSKMode(true);

        $skippedState = $this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $skippedState);

        $skippedState = $this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $skippedState);

        // 测试不能跳过的状态
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::INITIAL));
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_SERVER_HELLO));
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::CONNECTED));
    }

    /**
     * 测试处理PSK拒绝情况
     */
    public function testHandlePSKRejection(): void
    {
        // 设置PSK模式
        $this->stateMachine->setPSKMode(true);

        // 转换到等待加密扩展状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS);

        // 处理PSK拒绝
        $this->stateMachine->handlePSKRejection();

        // 验证PSK模式已被禁用
        // 这里我们通过检查状态跳过功能来验证PSK模式是否被禁用
        $skippedState = $this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE);
        $this->assertNull($skippedState); // PSK模式被禁用后，不能跳过证书状态

        // 测试在错误状态下处理PSK拒绝
        $this->stateMachine->transitionTo(HandshakeStateEnum::INITIAL);
        $this->stateMachine->setPSKMode(true); // 重新设置PSK模式
        $this->stateMachine->handlePSKRejection(); // 在非WAIT_ENCRYPTED_EXTENSIONS状态下调用，应该没有效果

        // 验证PSK模式仍然启用
        $skippedState = $this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $skippedState);
    }
}
