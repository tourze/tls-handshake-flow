<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Extension;

/**
 * 解码结果结构
 */
readonly class DecodeResult
{
    public function __construct(
        public int $value,
        public int $newOffset,
    ) {
    }
}
