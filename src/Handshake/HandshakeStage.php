<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Handshake;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * 握手阶段枚举
 */
enum HandshakeStage: int implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    /**
     * 握手阶段：初始阶段（交换 Hello 消息）
     */
    case INITIAL = 1;

    /**
     * 握手阶段：协商阶段（协商加密套件、协议版本等）
     */
    case NEGOTIATING = 2;

    /**
     * 握手阶段：密钥交换阶段
     */
    case KEY_EXCHANGE = 3;

    /**
     * 握手阶段：认证阶段
     */
    case AUTHENTICATION = 4;

    /**
     * 握手阶段：完成阶段
     */
    case FINISHED = 5;

    /**
     * 获取阶段标签
     *
     * @return string 阶段标签
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::INITIAL => '初始阶段',
            self::NEGOTIATING => '协商阶段',
            self::KEY_EXCHANGE => '密钥交换阶段',
            self::AUTHENTICATION => '认证阶段',
            self::FINISHED => '完成阶段',
        };
    }
}
