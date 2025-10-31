<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Extension;

/**
 * TLS 1.3后握手认证扩展
 *
 * 参考RFC 8446第4.2.6节
 * 此扩展用于指示客户端愿意在握手后接收CertificateRequest消息
 */
final class PostHandshakeAuthExtension extends AbstractExtension
{
    /**
     * 扩展类型
     */
    protected ExtensionType $type;

    public function __construct()
    {
        $this->type = ExtensionType::POST_HANDSHAKE_AUTH;
    }

    public function getType(): int
    {
        return $this->type->value;
    }

    public function encode(): string
    {
        // 后握手认证扩展没有内容
        return '';
    }

    /**
     * @return static
     */
    public static function decode(string $data): static
    {
        // 后握手认证扩展没有内容
        return new self();
    }

    public function isApplicableForVersion(string $tlsVersion): bool
    {
        // 后握手认证扩展仅适用于TLS 1.3及以上版本
        return '1.3' === $tlsVersion;
    }
}
