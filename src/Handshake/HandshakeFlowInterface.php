<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Handshake;

use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * 握手流程接口
 */
interface HandshakeFlowInterface
{
    /**
     * 握手阶段：初始阶段（交换 Hello 消息）
     */
    public const STAGE_INITIAL = 1;

    /**
     * 握手阶段：协商阶段（协商加密套件、协议版本等）
     */
    public const STAGE_NEGOTIATING = 2;

    /**
     * 握手阶段：密钥交换阶段
     */
    public const STAGE_KEY_EXCHANGE = 3;

    /**
     * 握手阶段：认证阶段
     */
    public const STAGE_AUTHENTICATION = 4;

    /**
     * 握手阶段：完成阶段
     */
    public const STAGE_FINISHED = 5;

    /**
     * 获取当前握手阶段
     *
     * @return HandshakeStage 当前阶段
     */
    public function getCurrentStage(): HandshakeStage;

    /**
     * 推进到指定阶段
     *
     * @param HandshakeStage $stage 目标阶段
     */
    public function advanceToStage(HandshakeStage $stage): void;

    /**
     * 检查特定阶段是否已完成
     *
     * @param HandshakeStage $stage 待检查的阶段
     */
    public function isStageCompleted(HandshakeStage $stage): bool;

    /**
     * 获取特定阶段预期的消息类型
     *
     * @param HandshakeStage $stage 阶段
     *
     * @return array<HandshakeMessageType> 消息类型列表
     */
    public function getExpectedMessageTypes(HandshakeStage $stage): array;

    /**
     * 检查当前阶段是否接受特定消息类型
     *
     * @param HandshakeMessageType $messageType 消息类型
     */
    public function acceptsMessageType(HandshakeMessageType $messageType): bool;
}
