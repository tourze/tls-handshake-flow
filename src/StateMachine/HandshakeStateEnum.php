<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\StateMachine;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * TLS握手状态枚举
 */
enum HandshakeStateEnum: string implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    /**
     * 初始状态
     */
    case INITIAL = 'INITIAL';

    /**
     * 等待服务器Hello消息
     */
    case WAIT_SERVER_HELLO = 'WAIT_SERVER_HELLO';

    /**
     * 等待证书消息
     */
    case WAIT_CERTIFICATE = 'WAIT_CERTIFICATE';

    /**
     * 等待服务器密钥交换消息
     */
    case WAIT_SERVER_KEY_EXCHANGE = 'WAIT_SERVER_KEY_EXCHANGE';

    /**
     * 等待服务器Hello完成消息
     */
    case WAIT_SERVER_HELLO_DONE = 'WAIT_SERVER_HELLO_DONE';

    /**
     * 等待客户端证书
     */
    case WAIT_CLIENT_CERTIFICATE = 'WAIT_CLIENT_CERTIFICATE';

    /**
     * 等待客户端密钥交换
     */
    case WAIT_CLIENT_KEY_EXCHANGE = 'WAIT_CLIENT_KEY_EXCHANGE';

    /**
     * 客户端提供了证书，等待密钥交换
     */
    case WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT = 'WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT';

    /**
     * 等待证书验证
     */
    case WAIT_CERTIFICATE_VERIFY = 'WAIT_CERTIFICATE_VERIFY';

    /**
     * 等待修改加密规范
     */
    case WAIT_CHANGE_CIPHER_SPEC = 'WAIT_CHANGE_CIPHER_SPEC';

    /**
     * 等待握手完成消息
     */
    case WAIT_FINISHED = 'WAIT_FINISHED';

    /**
     * 等待客户端握手完成消息
     */
    case WAIT_CLIENT_FINISHED = 'WAIT_CLIENT_FINISHED';

    /**
     * TLS连接已建立
     */
    case CONNECTED = 'CONNECTED';

    /**
     * 握手错误状态
     */
    case ERROR = 'ERROR';

    /**
     * TLS 1.3特有：等待加密扩展
     */
    case WAIT_ENCRYPTED_EXTENSIONS = 'WAIT_ENCRYPTED_EXTENSIONS';

    /**
     * TLS 1.3特有：等待新的会话凭证
     */
    case WAIT_NEW_SESSION_TICKET = 'WAIT_NEW_SESSION_TICKET';

    /**
     * TLS 1.3特有：正在处理早期数据(0-RTT)
     */
    case PROCESS_EARLY_DATA = 'PROCESS_EARLY_DATA';

    /**
     * TLS 1.3特有：等待客户端证书验证
     */
    case WAIT_CLIENT_VERIFY = 'WAIT_CLIENT_VERIFY';

    /**
     * 获取状态标签
     *
     * @return string 状态标签
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::INITIAL => '初始状态',
            self::WAIT_SERVER_HELLO => '等待服务器Hello',
            self::WAIT_CERTIFICATE => '等待证书',
            self::WAIT_SERVER_KEY_EXCHANGE => '等待服务器密钥交换',
            self::WAIT_SERVER_HELLO_DONE => '等待服务器Hello完成',
            self::WAIT_CLIENT_CERTIFICATE => '等待客户端证书',
            self::WAIT_CLIENT_KEY_EXCHANGE => '等待客户端密钥交换',
            self::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT => '等待客户端密钥交换(含证书)',
            self::WAIT_CERTIFICATE_VERIFY => '等待证书验证',
            self::WAIT_CHANGE_CIPHER_SPEC => '等待修改加密规范',
            self::WAIT_FINISHED => '等待握手完成',
            self::WAIT_CLIENT_FINISHED => '等待客户端握手完成',
            self::CONNECTED => '已连接',
            self::ERROR => '错误状态',
            self::WAIT_ENCRYPTED_EXTENSIONS => '等待加密扩展',
            self::WAIT_NEW_SESSION_TICKET => '等待新会话票据',
            self::PROCESS_EARLY_DATA => '处理早期数据',
            self::WAIT_CLIENT_VERIFY => '等待客户端验证',
        };
    }
}
