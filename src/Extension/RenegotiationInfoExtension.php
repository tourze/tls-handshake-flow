<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Extension;

use Tourze\TLSHandshakeFlow\Exception\InvalidHandshakeDataException;

/**
 * 安全重协商信息扩展
 *
 * 实现RFC 5746规定的TLS安全重协商扩展
 * 该扩展用于防止TLS重协商中的中间人攻击
 */
final class RenegotiationInfoExtension extends AbstractExtension
{
    /**
     * 重协商连接数据
     *
     * 初始握手时为空
     * 重协商时，客户端提供已验证的finished消息
     */
    private string $renegotiatedConnection = '';

    /**
     * 扩展类型
     */
    protected ExtensionType $type;

    public function __construct()
    {
        $this->type = ExtensionType::RENEGOTIATION_INFO;
    }

    public function getType(): int
    {
        return $this->type->value;
    }

    /**
     * 设置重协商连接数据
     *
     * @param string $data 重协商连接数据
     */
    public function setRenegotiatedConnection(string $data): void
    {
        $this->renegotiatedConnection = $data;
    }

    /**
     * 获取重协商连接数据
     *
     * @return string 重协商连接数据
     */
    public function getRenegotiatedConnection(): string
    {
        return $this->renegotiatedConnection;
    }

    public function encode(): string
    {
        // 重协商信息格式:
        // 1字节长度 + 数据
        $length = strlen($this->renegotiatedConnection);

        return chr($length) . $this->renegotiatedConnection;
    }

    /**
     * @return static
     */
    public static function decode(string $data): static
    {
        if (strlen($data) < 1) {
            throw new InvalidHandshakeDataException('安全重协商扩展数据不完整');
        }

        // 读取长度字节
        $length = ord($data[0]);

        // 验证数据长度
        if (strlen($data) - 1 < $length) {
            throw new InvalidHandshakeDataException('安全重协商扩展数据长度与实际不符');
        }

        $extension = new self();
        if ($length > 0) {
            $extension->setRenegotiatedConnection(substr($data, 1, $length));
        }

        return $extension;
    }
}
