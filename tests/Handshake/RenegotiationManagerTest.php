<?php

namespace Tourze\TLSHandshakeFlow\Tests\Handshake;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Extension\RenegotiationInfoExtension;
use Tourze\TLSHandshakeFlow\Handshake\RenegotiationManager;
use Tourze\TLSHandshakeFlow\Protocol\TLSVersion;

/**
 * 重协商管理器测试类
 *
 * @internal
 */
#[CoversClass(RenegotiationManager::class)]
final class RenegotiationManagerTest extends TestCase
{
    /**
     * 测试创建重协商管理器
     */
    public function testCreateRenegotiationManager(): void
    {
        $manager = new RenegotiationManager();
        $this->assertFalse($manager->isRenegotiating());
        $this->assertFalse($manager->isSecureRenegotiation());
    }

    /**
     * 测试设置安全重协商
     */
    public function testSetSecureRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);
        $this->assertTrue($manager->isSecureRenegotiation());

        $manager->setSecureRenegotiation(false);
        $this->assertFalse($manager->isSecureRenegotiation());
    }

    /**
     * 测试开始重协商
     */
    public function testStartRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $this->assertFalse($manager->isRenegotiating());

        $manager->startRenegotiation();
        $this->assertTrue($manager->isRenegotiating());
    }

    /**
     * 测试结束重协商
     */
    public function testEndRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $manager->startRenegotiation();
        $this->assertTrue($manager->isRenegotiating());

        $manager->endRenegotiation();
        $this->assertFalse($manager->isRenegotiating());
    }

    /**
     * 测试生成初始安全重协商扩展
     */
    public function testCreateInitialRenegotiationInfoExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);

        $extension = $manager->createRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEmpty($extension->getRenegotiatedConnection());
    }

    /**
     * 测试处理客户端重协商扩展
     */
    public function testProcessClientRenegotiationExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);

        // 第一次握手，客户端的扩展应该为空
        $clientExtension = new RenegotiationInfoExtension();
        $result = $manager->processClientRenegotiationExtension($clientExtension);
        $this->assertTrue($result);

        // 模拟重协商
        $manager->storeClientVerifyData('client_verify_data');
        $manager->storeServerVerifyData('server_verify_data');
        $manager->startRenegotiation();

        // 客户端应该提供正确的验证数据
        $correctData = 'client_verify_data';
        $clientExtension = new RenegotiationInfoExtension();
        $clientExtension->setRenegotiatedConnection($correctData);
        $result = $manager->processClientRenegotiationExtension($clientExtension);
        $this->assertTrue($result);

        // 错误的验证数据应该被拒绝
        $incorrectData = 'wrong_verify_data';
        $clientExtension = new RenegotiationInfoExtension();
        $clientExtension->setRenegotiatedConnection($incorrectData);
        $result = $manager->processClientRenegotiationExtension($clientExtension);
        $this->assertFalse($result);
    }

    /**
     * 测试生成服务器重协商扩展
     */
    public function testCreateServerRenegotiationExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);

        // 初始握手
        $extension = $manager->createServerRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEmpty($extension->getRenegotiatedConnection());

        // 模拟重协商
        $manager->storeClientVerifyData('client_verify_data');
        $manager->storeServerVerifyData('server_verify_data');
        $manager->startRenegotiation();

        // 重协商时，服务器应提供客户端和服务器的验证数据
        $extension = $manager->createServerRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEquals('client_verify_dataserver_verify_data', $extension->getRenegotiatedConnection());
    }

    /**
     * 测试重协商次数限制
     */
    public function testRenegotiationLimits(): void
    {
        $manager = new RenegotiationManager();
        $manager->setRenegotiationLimit(2);

        // 第一次重协商
        $this->assertTrue($manager->canRenegotiate());
        $manager->incrementRenegotiationCount();

        // 第二次重协商
        $this->assertTrue($manager->canRenegotiate());
        $manager->incrementRenegotiationCount();

        // 第三次重协商应该被拒绝
        $this->assertFalse($manager->canRenegotiate());
    }

    /**
     * 测试TLS 1.3不支持重协商
     */
    public function testTLS13NoRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $this->assertFalse($manager->isSupportedForVersion(TLSVersion::TLS_1_3));
        $this->assertTrue($manager->isSupportedForVersion(TLSVersion::TLS_1_2));
    }

    /**
     * 测试获取客户端验证数据
     */
    public function testGetClientVerifyData(): void
    {
        $manager = new RenegotiationManager();

        // 初始状态应该为空
        $this->assertEquals('', $manager->getClientVerifyData());

        // 存储数据后应该能获取到
        $testData = 'client_verify_test_data';
        $manager->storeClientVerifyData($testData);
        $this->assertEquals($testData, $manager->getClientVerifyData());
    }

    /**
     * 测试获取服务器验证数据
     */
    public function testGetServerVerifyData(): void
    {
        $manager = new RenegotiationManager();

        // 初始状态应该为空
        $this->assertEquals('', $manager->getServerVerifyData());

        // 存储数据后应该能获取到
        $testData = 'server_verify_test_data';
        $manager->storeServerVerifyData($testData);
        $this->assertEquals($testData, $manager->getServerVerifyData());
    }

    /**
     * 测试处理服务器重协商扩展
     */
    public function testProcessServerRenegotiationExtension(): void
    {
        $manager = new RenegotiationManager();

        // 未启用安全重协商，应该返回false
        $extension = new RenegotiationInfoExtension();
        $this->assertFalse($manager->processServerRenegotiationExtension($extension));

        // 启用安全重协商
        $manager->setSecureRenegotiation(true);

        // 初始握手，服务器扩展应该为空
        $extension = new RenegotiationInfoExtension();
        $this->assertTrue($manager->processServerRenegotiationExtension($extension));

        // 初始握手，服务器扩展不为空应该失败
        $extension = new RenegotiationInfoExtension();
        $extension->setRenegotiatedConnection('not_empty');
        $this->assertFalse($manager->processServerRenegotiationExtension($extension));

        // 模拟重协商
        $manager->storeClientVerifyData('client_data');
        $manager->storeServerVerifyData('server_data');
        $manager->startRenegotiation();

        // 重协商时，服务器应该提供正确的验证数据
        $extension = new RenegotiationInfoExtension();
        $extension->setRenegotiatedConnection('client_dataserver_data');
        $this->assertTrue($manager->processServerRenegotiationExtension($extension));

        // 错误的验证数据应该被拒绝
        $extension = new RenegotiationInfoExtension();
        $extension->setRenegotiatedConnection('wrong_data');
        $this->assertFalse($manager->processServerRenegotiationExtension($extension));
    }

    /**
     * 测试链式调用
     */
    public function testFluentInterface(): void
    {
        $manager = new RenegotiationManager();

        // 设置返回void的方法
        $manager->setSecureRenegotiation(true);
        $manager->setRenegotiationLimit(5);

        // 测试其他返回self的方法仍可以链式调用
        $result = $manager
            ->storeClientVerifyData('client_data')
            ->storeServerVerifyData('server_data')
            ->startRenegotiation()
            ->incrementRenegotiationCount()
            ->endRenegotiation()
        ;

        $this->assertSame($manager, $result);

        // 验证设置生效
        $this->assertTrue($manager->isSecureRenegotiation());
        $this->assertEquals('client_data', $manager->getClientVerifyData());
        $this->assertEquals('server_data', $manager->getServerVerifyData());
        $this->assertFalse($manager->isRenegotiating());
    }

    /**
     * 测试重协商计数重置场景
     */
    public function testRenegotiationCountReset(): void
    {
        $manager = new RenegotiationManager();
        $manager->setRenegotiationLimit(1);

        // 达到限制
        $manager->incrementRenegotiationCount();
        $this->assertFalse($manager->canRenegotiate());

        // 创建新的管理器实例（模拟连接重置）
        $newManager = new RenegotiationManager();
        $newManager->setRenegotiationLimit(1);
        $this->assertTrue($newManager->canRenegotiate());
    }

    public function testCanRenegotiate(): void
    {
        $manager = new RenegotiationManager();
        $manager->setRenegotiationLimit(2);

        $this->assertTrue($manager->canRenegotiate());

        $manager->incrementRenegotiationCount();
        $this->assertTrue($manager->canRenegotiate());

        $manager->incrementRenegotiationCount();
        $this->assertFalse($manager->canRenegotiate());
    }

    public function testCreateRenegotiationInfoExtension(): void
    {
        $manager = new RenegotiationManager();
        $extension = $manager->createRenegotiationInfoExtension();

        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEmpty($extension->getRenegotiatedConnection());
    }

    public function testCreateServerRenegotiationInfoExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);

        $extension = $manager->createServerRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEmpty($extension->getRenegotiatedConnection());

        $manager->storeClientVerifyData('client_data');
        $manager->storeServerVerifyData('server_data');
        $manager->startRenegotiation();

        $extension = $manager->createServerRenegotiationInfoExtension();
        $this->assertEquals('client_dataserver_data', $extension->getRenegotiatedConnection());
    }

    public function testIncrementRenegotiationCount(): void
    {
        $manager = new RenegotiationManager();
        $manager->setRenegotiationLimit(3);

        $this->assertTrue($manager->canRenegotiate());

        $result = $manager->incrementRenegotiationCount();
        $this->assertSame($manager, $result);
        $this->assertTrue($manager->canRenegotiate());

        $manager->incrementRenegotiationCount();
        $this->assertTrue($manager->canRenegotiate());

        $manager->incrementRenegotiationCount();
        $this->assertFalse($manager->canRenegotiate());
    }

    public function testStoreClientVerifyData(): void
    {
        $manager = new RenegotiationManager();
        $testData = 'client_verify_data_test';

        $this->assertEquals('', $manager->getClientVerifyData());

        $result = $manager->storeClientVerifyData($testData);
        $this->assertSame($manager, $result);
        $this->assertEquals($testData, $manager->getClientVerifyData());
    }

    public function testStoreServerVerifyData(): void
    {
        $manager = new RenegotiationManager();
        $testData = 'server_verify_data_test';

        $this->assertEquals('', $manager->getServerVerifyData());

        $result = $manager->storeServerVerifyData($testData);
        $this->assertSame($manager, $result);
        $this->assertEquals($testData, $manager->getServerVerifyData());
    }
}
