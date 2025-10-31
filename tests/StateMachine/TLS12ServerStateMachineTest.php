<?php

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshakeFlow\StateMachine\TLS12ServerStateMachine;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * @internal
 */
#[CoversClass(TLS12ServerStateMachine::class)]
final class TLS12ServerStateMachineTest extends TestCase
{
    private TLS12ServerStateMachine $stateMachine;

    /**
     * 设置测试用例
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->stateMachine = new TLS12ServerStateMachine();
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
     * 测试完整的TLS 1.2握手流程
     */
    public function testCompleteTLS12Handshake(): void
    {
        // 初始状态 -> WAIT_SERVER_HELLO (接收CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_CERTIFICATE (发送SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE -> WAIT_SERVER_KEY_EXCHANGE (发送CERTIFICATE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_KEY_EXCHANGE -> WAIT_SERVER_HELLO_DONE (发送SERVER_KEY_EXCHANGE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO_DONE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO_DONE -> WAIT_CLIENT_KEY_EXCHANGE (发送SERVER_HELLO_DONE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO_DONE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CLIENT_KEY_EXCHANGE -> WAIT_CHANGE_CIPHER_SPEC (接收CLIENT_KEY_EXCHANGE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 模拟接收CHANGE_CIPHER_SPEC (不是握手消息，但需要转换状态)
        $this->stateMachine->processChangeCipherSpec();
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $this->stateMachine->getCurrentState());

        // WAIT_FINISHED -> WAIT_CLIENT_FINISHED (接收客户端FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 模拟服务器发送自己的ChangeCipherSpec和Finished
        $this->stateMachine->prepareServerFinished();
        $this->assertEquals(HandshakeStateEnum::CONNECTED, $this->stateMachine->getCurrentState());

        // 确认握手已完成
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    /**
     * 测试使用客户端证书的握手流程
     */
    public function testHandshakeWithClientCertificate(): void
    {
        // 省略前面的步骤，直接到WAIT_SERVER_KEY_EXCHANGE
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE);

        // 发送证书请求
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_REQUEST);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO_DONE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 继续正常流程到WAIT_CLIENT_KEY_EXCHANGE
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE);

        // 接收客户端证书
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 接收客户端密钥交换
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 接收证书验证
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 继续正常握手流程
        $this->stateMachine->processChangeCipherSpec();
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $this->stateMachine->getCurrentState());
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
     * 测试重置功能
     */
    public function testReset(): void
    {
        // 先转换到错误状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::ERROR);
        $this->assertTrue($this->stateMachine->isInErrorState());

        // 重置
        $this->stateMachine->reset();
        $this->assertEquals(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    /**
     * 测试是否可以跳过状态
     */
    public function testCanSkipState(): void
    {
        // 测试可以跳过的状态
        $skippedState = $this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO_DONE, $skippedState);

        $skippedState = $this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC, $skippedState);

        // 测试不能跳过的状态
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::INITIAL));
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::WAIT_SERVER_HELLO));
        $this->assertNull($this->stateMachine->canSkipState(HandshakeStateEnum::CONNECTED));
    }

    /**
     * 测试处理ChangeCipherSpec消息
     */
    public function testProcessChangeCipherSpec(): void
    {
        // 正常情况：从WAIT_CHANGE_CIPHER_SPEC状态处理ChangeCipherSpec
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC);
        $this->stateMachine->processChangeCipherSpec();
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $this->stateMachine->getCurrentState());

        // 异常情况：在错误的状态下处理ChangeCipherSpec
        $this->stateMachine->transitionTo(HandshakeStateEnum::INITIAL);
        $this->stateMachine->processChangeCipherSpec();
        $this->assertEquals(HandshakeStateEnum::ERROR, $this->stateMachine->getCurrentState());
        $this->assertTrue($this->stateMachine->isInErrorState());
    }

    /**
     * 测试准备服务器Finished消息
     */
    public function testPrepareServerFinished(): void
    {
        // 正常情况：从WAIT_CLIENT_FINISHED状态准备服务器Finished
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_CLIENT_FINISHED);
        $this->stateMachine->prepareServerFinished();
        $this->assertEquals(HandshakeStateEnum::CONNECTED, $this->stateMachine->getCurrentState());
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());

        // 异常情况：在错误的状态下准备服务器Finished
        $this->stateMachine->transitionTo(HandshakeStateEnum::INITIAL);
        $this->stateMachine->prepareServerFinished();
        $this->assertEquals(HandshakeStateEnum::ERROR, $this->stateMachine->getCurrentState());
        $this->assertTrue($this->stateMachine->isInErrorState());
    }
}
