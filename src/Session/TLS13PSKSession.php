<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Session;

/**
 * TLS 1.3 PSK会话接口
 *
 * 此接口定义了TLS 1.3中预共享密钥(PSK)会话所需的基本方法
 */
interface TLS13PSKSession
{
    /**
     * 获取PSK身份
     *
     * @return string PSK身份
     */
    public function getPskIdentity(): string;

    /**
     * 获取会话时间戳
     *
     * @return int 会话创建时间戳
     */
    public function getTimestamp(): int;

    /**
     * 获取最大早期数据大小
     *
     * @return int 最大早期数据大小（字节）
     */
    public function getMaxEarlyDataSize(): int;
}
