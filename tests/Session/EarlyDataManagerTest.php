<?php

namespace Tourze\TLSHandshakeFlow\Tests\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Session\EarlyDataManager;
use Tourze\TLSHandshakeFlow\Session\TLS13PSKSession;

/**
 * 早期数据管理器测试
 *
 * @internal
 */
#[CoversClass(EarlyDataManager::class)]
final class EarlyDataManagerTest extends TestCase
{
    /**
     * @var TLS13PSKSession&MockObject
     */
    private $mockSession;

    protected function setUp(): void
    {
        parent::setUp();
        // 这里使用具体类 TLS13PSKSession 的 Mock 是因为：
        // 1. 该类是 TLS 1.3 PSK 会话的具体实现，没有通用的会话接口
        // 2. 早期数据管理器需要访问 PSK 会话的特定方法（如 getPskIdentity、getMaxEarlyDataSize）
        // 3. 测试需要验证与真实 TLS 1.3 会话对象的交互，确保早期数据验证的正确性
        /* @phpstan-ignore-next-line */
        $this->mockSession = $this->createMock(TLS13PSKSession::class);
        $this->mockSession->method('getPskIdentity')->willReturn('test-psk-id');
        $this->mockSession->method('getMaxEarlyDataSize')->willReturn(16384); // 16KB
        $this->mockSession->method('getTimestamp')->willReturn(time());
    }

    public function testStoreAndRetrieveData(): void
    {
        $manager = new EarlyDataManager();
        $data = 'Test early data content';

        // 存储早期数据
        $dataId = $manager->storeEarlyData($this->mockSession, $data);
        $this->assertNotEmpty($dataId);

        // 验证并获取数据
        $retrievedData = $manager->getAndValidateEarlyData($this->mockSession, $dataId);
        $this->assertEquals($data, $retrievedData);
    }

    public function testRejectionOfUsedData(): void
    {
        $manager = new EarlyDataManager();
        $data = 'Test early data for rejection';

        // 存储早期数据
        $dataId = $manager->storeEarlyData($this->mockSession, $data);

        // 第一次验证应该成功
        $firstAttempt = $manager->getAndValidateEarlyData($this->mockSession, $dataId);
        $this->assertEquals($data, $firstAttempt);

        // 第二次验证应该失败（防止重放攻击）
        $secondAttempt = $manager->getAndValidateEarlyData($this->mockSession, $dataId);
        $this->assertNull($secondAttempt);
    }

    public function testRejectionOfInvalidId(): void
    {
        $manager = new EarlyDataManager();

        // 使用不存在的ID验证
        $result = $manager->getAndValidateEarlyData($this->mockSession, 'non-existent-id');
        $this->assertNull($result);
    }

    public function testRejectionOfMismatchedPskIdentity(): void
    {
        $manager = new EarlyDataManager();
        $data = 'Test early data for identity mismatch';

        // 存储早期数据
        $dataId = $manager->storeEarlyData($this->mockSession, $data);

        // 创建不同PSK身份的会话
        // 这里使用具体类 TLS13PSKSession 的 Mock 是因为：
        // 1. 需要测试不同 PSK 身份的会话验证，这是 TLS 1.3 的具体实现
        // 2. 早期数据验证依赖于具体的 PSK 身份比较逻辑
        // 3. 测试需要模拟真实的会话身份不匹配场景，确保安全性验证的正确性
        /** @var TLS13PSKSession&MockObject $differentSession */
        /** @phpstan-ignore-next-line */
        $differentSession = $this->createMock(TLS13PSKSession::class);
        $differentSession->method('getPskIdentity')->willReturn('different-psk-id');
        $differentSession->method('getMaxEarlyDataSize')->willReturn(16384);
        $differentSession->method('getTimestamp')->willReturn(time());

        // 不同身份的会话应该被拒绝
        $result = $manager->getAndValidateEarlyData($differentSession, $dataId);
        $this->assertNull($result);
    }

    public function testClearAllData(): void
    {
        $manager = new EarlyDataManager();
        $data = 'Test early data for clear all';

        // 存储早期数据
        $dataId = $manager->storeEarlyData($this->mockSession, $data);

        // 清除所有数据
        $manager->clearAllEarlyData();

        // 应该无法获取数据
        $result = $manager->getAndValidateEarlyData($this->mockSession, $dataId);
        $this->assertNull($result);
    }

    public function testClearAllEarlyData(): void
    {
        $manager = new EarlyDataManager();
        $data1 = 'Test early data 1';
        $data2 = 'Test early data 2';

        // 存储多个早期数据
        $dataId1 = $manager->storeEarlyData($this->mockSession, $data1);
        $dataId2 = $manager->storeEarlyData($this->mockSession, $data2);

        // 验证数据可以获取
        $this->assertEquals($data1, $manager->getAndValidateEarlyData($this->mockSession, $dataId1));

        // 清除所有早期数据
        $manager->clearAllEarlyData();

        // 所有数据都应该无法获取
        $this->assertNull($manager->getAndValidateEarlyData($this->mockSession, $dataId1));
        $this->assertNull($manager->getAndValidateEarlyData($this->mockSession, $dataId2));
    }

    public function testStoreEarlyData(): void
    {
        $manager = new EarlyDataManager();
        $data = 'Test early data for store';

        // 存储早期数据
        $dataId = $manager->storeEarlyData($this->mockSession, $data);

        // 验证返回的ID不为空
        $this->assertNotEmpty($dataId);
        $this->assertIsString($dataId);

        // 验证可以通过ID获取数据
        $retrievedData = $manager->getAndValidateEarlyData($this->mockSession, $dataId);
        $this->assertEquals($data, $retrievedData);
    }
}
