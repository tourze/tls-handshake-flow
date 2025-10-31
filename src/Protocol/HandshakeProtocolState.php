<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Protocol;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * 握手协议状态枚举
 */
enum HandshakeProtocolState: int implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    /**
     * 握手状态：未开始
     */
    case NOT_STARTED = 0;

    /**
     * 握手状态：进行中
     */
    case IN_PROGRESS = 1;

    /**
     * 握手状态：已完成
     */
    case COMPLETED = 2;

    /**
     * 握手状态：失败
     */
    case FAILED = 3;

    /**
     * 获取状态标签
     *
     * @return string 状态标签
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::NOT_STARTED => '未开始',
            self::IN_PROGRESS => '进行中',
            self::COMPLETED => '已完成',
            self::FAILED => '失败',
        };
    }
}
