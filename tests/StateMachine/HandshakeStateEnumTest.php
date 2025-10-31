<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;

/**
 * @internal
 */
#[CoversClass(HandshakeStateEnum::class)]
final class HandshakeStateEnumTest extends AbstractEnumTestCase
{
    public function testImplementsInterfaces(): void
    {
        $this->assertInstanceOf(Itemable::class, HandshakeStateEnum::INITIAL);
        $this->assertInstanceOf(Labelable::class, HandshakeStateEnum::INITIAL);
        $this->assertInstanceOf(Selectable::class, HandshakeStateEnum::INITIAL);
    }

    public function testEnumValues(): void
    {
        $this->assertSame('INITIAL', HandshakeStateEnum::INITIAL->value);
        $this->assertSame('WAIT_SERVER_HELLO', HandshakeStateEnum::WAIT_SERVER_HELLO->value);
        $this->assertSame('WAIT_CERTIFICATE', HandshakeStateEnum::WAIT_CERTIFICATE->value);
        $this->assertSame('WAIT_SERVER_KEY_EXCHANGE', HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE->value);
        $this->assertSame('WAIT_SERVER_HELLO_DONE', HandshakeStateEnum::WAIT_SERVER_HELLO_DONE->value);
        $this->assertSame('WAIT_CLIENT_CERTIFICATE', HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE->value);
        $this->assertSame('WAIT_CLIENT_KEY_EXCHANGE', HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE->value);
        $this->assertSame('WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT', HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT->value);
        $this->assertSame('WAIT_CERTIFICATE_VERIFY', HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->value);
        $this->assertSame('WAIT_CHANGE_CIPHER_SPEC', HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC->value);
        $this->assertSame('WAIT_FINISHED', HandshakeStateEnum::WAIT_FINISHED->value);
        $this->assertSame('WAIT_CLIENT_FINISHED', HandshakeStateEnum::WAIT_CLIENT_FINISHED->value);
        $this->assertSame('CONNECTED', HandshakeStateEnum::CONNECTED->value);
        $this->assertSame('ERROR', HandshakeStateEnum::ERROR->value);
        $this->assertSame('WAIT_ENCRYPTED_EXTENSIONS', HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value);
        $this->assertSame('WAIT_NEW_SESSION_TICKET', HandshakeStateEnum::WAIT_NEW_SESSION_TICKET->value);
        $this->assertSame('PROCESS_EARLY_DATA', HandshakeStateEnum::PROCESS_EARLY_DATA->value);
        $this->assertSame('WAIT_CLIENT_VERIFY', HandshakeStateEnum::WAIT_CLIENT_VERIFY->value);
    }

    public function testGetLabel(): void
    {
        $this->assertSame('初始状态', HandshakeStateEnum::INITIAL->getLabel());
        $this->assertSame('等待服务器Hello', HandshakeStateEnum::WAIT_SERVER_HELLO->getLabel());
        $this->assertSame('等待证书', HandshakeStateEnum::WAIT_CERTIFICATE->getLabel());
        $this->assertSame('等待服务器密钥交换', HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE->getLabel());
        $this->assertSame('等待服务器Hello完成', HandshakeStateEnum::WAIT_SERVER_HELLO_DONE->getLabel());
        $this->assertSame('等待客户端证书', HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE->getLabel());
        $this->assertSame('等待客户端密钥交换', HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE->getLabel());
        $this->assertSame('等待客户端密钥交换(含证书)', HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT->getLabel());
        $this->assertSame('等待证书验证', HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->getLabel());
        $this->assertSame('等待修改加密规范', HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC->getLabel());
        $this->assertSame('等待握手完成', HandshakeStateEnum::WAIT_FINISHED->getLabel());
        $this->assertSame('等待客户端握手完成', HandshakeStateEnum::WAIT_CLIENT_FINISHED->getLabel());
        $this->assertSame('已连接', HandshakeStateEnum::CONNECTED->getLabel());
        $this->assertSame('错误状态', HandshakeStateEnum::ERROR->getLabel());
        $this->assertSame('等待加密扩展', HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS->getLabel());
        $this->assertSame('等待新会话票据', HandshakeStateEnum::WAIT_NEW_SESSION_TICKET->getLabel());
        $this->assertSame('处理早期数据', HandshakeStateEnum::PROCESS_EARLY_DATA->getLabel());
        $this->assertSame('等待客户端验证', HandshakeStateEnum::WAIT_CLIENT_VERIFY->getLabel());
    }

    public function testAllCasesHaveLabels(): void
    {
        foreach (HandshakeStateEnum::cases() as $case) {
            $this->assertNotEmpty($case->getLabel(), "Handshake state {$case->name} should have a label");
        }
    }

    public function testFromValue(): void
    {
        $this->assertSame(HandshakeStateEnum::INITIAL, HandshakeStateEnum::from('INITIAL'));
        $this->assertSame(HandshakeStateEnum::WAIT_SERVER_HELLO, HandshakeStateEnum::from('WAIT_SERVER_HELLO'));
        $this->assertSame(HandshakeStateEnum::CONNECTED, HandshakeStateEnum::from('CONNECTED'));
        $this->assertSame(HandshakeStateEnum::ERROR, HandshakeStateEnum::from('ERROR'));
    }

    public function testTryFromValue(): void
    {
        $this->assertSame(HandshakeStateEnum::INITIAL, HandshakeStateEnum::tryFrom('INITIAL'));
        $this->assertNull(HandshakeStateEnum::tryFrom('INVALID_STATE'));
    }

    public function testTLS12SpecificStates(): void
    {
        $tls12States = [
            HandshakeStateEnum::WAIT_SERVER_HELLO,
            HandshakeStateEnum::WAIT_CERTIFICATE,
            HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE,
            HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
            HandshakeStateEnum::WAIT_FINISHED,
        ];

        foreach ($tls12States as $state) {
            $this->assertNotEmpty($state->getLabel());
            $this->assertInstanceOf(HandshakeStateEnum::class, $state);
        }
    }

    public function testTLS13SpecificStates(): void
    {
        $tls13States = [
            HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
            HandshakeStateEnum::PROCESS_EARLY_DATA,
            HandshakeStateEnum::WAIT_CLIENT_VERIFY,
        ];

        foreach ($tls13States as $state) {
            $this->assertNotEmpty($state->getLabel());
            $this->assertInstanceOf(HandshakeStateEnum::class, $state);
        }
    }

    public function testTerminalStates(): void
    {
        $terminalStates = [
            HandshakeStateEnum::CONNECTED,
            HandshakeStateEnum::ERROR,
        ];

        foreach ($terminalStates as $state) {
            $this->assertNotEmpty($state->getLabel());
            $this->assertInstanceOf(HandshakeStateEnum::class, $state);
        }
    }

    public function testUniqueValues(): void
    {
        $values = [];
        foreach (HandshakeStateEnum::cases() as $case) {
            $this->assertNotContains($case->value, $values, "Value {$case->value} should be unique");
            $values[] = $case->value;
        }
    }

    /**
     * 测试 toArray 方法
     */
    public function testToArray(): void
    {
        $result = HandshakeStateEnum::INITIAL->toArray();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('value', $result);
        $this->assertArrayHasKey('label', $result);

        $this->assertSame('INITIAL', $result['value']);
        $this->assertSame('初始状态', $result['label']);

        // 测试另一个枚举值
        $result2 = HandshakeStateEnum::CONNECTED->toArray();
        $this->assertSame('CONNECTED', $result2['value']);
        $this->assertSame('已连接', $result2['label']);
    }

    /**
     * 测试 toSelectItem 方法
     */
}
