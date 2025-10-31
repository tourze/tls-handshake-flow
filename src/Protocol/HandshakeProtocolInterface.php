<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Protocol;

/**
 * TLS握手协议接口
 */
interface HandshakeProtocolInterface
{
    /**
     * 开始握手流程
     */
    public function startHandshake(): void;

    /**
     * 处理收到的握手消息
     *
     * @param string $message 握手消息数据
     *
     * @return string|null 返回响应消息，如果没有则返回null
     */
    public function processHandshakeMessage(string $message): ?string;

    /**
     * 获取当前握手状态
     *
     * @return HandshakeProtocolState 当前状态
     */
    public function getState(): HandshakeProtocolState;

    /**
     * 握手是否已完成
     */
    public function isHandshakeCompleted(): bool;

    /**
     * 标记握手过程已完成
     */
    public function completeHandshake(): void;

    /**
     * 获取协议版本
     */
    public function getVersion(): ?string;

    /**
     * 设置协议版本
     *
     * @param string $version 协议版本
     */
    public function setVersion(string $version): void;
}
