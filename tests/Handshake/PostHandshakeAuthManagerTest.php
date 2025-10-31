<?php

namespace Tourze\TLSHandshakeFlow\Tests\Handshake;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\Extension\PostHandshakeAuthExtension;
use Tourze\TLSHandshakeFlow\Handshake\PostHandshakeAuthManager;
use Tourze\TLSHandshakeFlow\Protocol\TLSVersion;

/**
 * 后握手认证管理器测试
 *
 * @internal
 */
#[CoversClass(PostHandshakeAuthManager::class)]
final class PostHandshakeAuthManagerTest extends TestCase
{
    public function testDefaultDisabled(): void
    {
        $manager = new PostHandshakeAuthManager();
        $this->assertFalse($manager->isEnabled());
    }

    public function testEnableDisable(): void
    {
        $manager = new PostHandshakeAuthManager();

        $manager->setEnabled(true);
        $this->assertTrue($manager->isEnabled());

        $manager->setEnabled(false);
        $this->assertFalse($manager->isEnabled());
    }

    public function testCertificateRequestState(): void
    {
        $manager = new PostHandshakeAuthManager();

        $this->assertFalse($manager->isRequestingCertificate());

        $manager->requestClientCertificate();
        $this->assertTrue($manager->isRequestingCertificate());

        $manager->resetCertificateRequest();
        $this->assertFalse($manager->isRequestingCertificate());
    }

    public function testRequestClientCertificate(): void
    {
        $manager = new PostHandshakeAuthManager();

        $this->assertFalse($manager->isRequestingCertificate());

        $result = $manager->requestClientCertificate();
        $this->assertSame($manager, $result);
        $this->assertTrue($manager->isRequestingCertificate());
    }

    public function testResetCertificateRequest(): void
    {
        $manager = new PostHandshakeAuthManager();
        $manager->requestClientCertificate();
        $this->assertTrue($manager->isRequestingCertificate());

        $result = $manager->resetCertificateRequest();
        $this->assertSame($manager, $result);
        $this->assertFalse($manager->isRequestingCertificate());
    }

    public function testVersionSupport(): void
    {
        $manager = new PostHandshakeAuthManager();

        $this->assertFalse($manager->isSupportedForVersion(TLSVersion::TLS_1_0));
        $this->assertFalse($manager->isSupportedForVersion(TLSVersion::TLS_1_1));
        $this->assertFalse($manager->isSupportedForVersion(TLSVersion::TLS_1_2));
        $this->assertTrue($manager->isSupportedForVersion(TLSVersion::TLS_1_3));
    }

    public function testCreateExtension(): void
    {
        $manager = new PostHandshakeAuthManager();
        $extension = $manager->createPostHandshakeAuthExtension();

        $this->assertInstanceOf(PostHandshakeAuthExtension::class, $extension);
    }

    public function testCreatePostHandshakeAuthExtension(): void
    {
        $manager = new PostHandshakeAuthManager();
        $extension = $manager->createPostHandshakeAuthExtension();

        $this->assertInstanceOf(PostHandshakeAuthExtension::class, $extension);
    }

    public function testProcessClientExtension(): void
    {
        $manager = new PostHandshakeAuthManager();
        $extension = new PostHandshakeAuthExtension();

        $this->assertTrue($manager->processClientPostHandshakeAuthExtension($extension));
        $this->assertTrue($manager->isEnabled());

        $this->assertFalse($manager->processClientPostHandshakeAuthExtension(null));
        $this->assertFalse($manager->isEnabled());
    }

    public function testProcessClientPostHandshakeAuthExtension(): void
    {
        $manager = new PostHandshakeAuthManager();
        $extension = new PostHandshakeAuthExtension();

        $this->assertTrue($manager->processClientPostHandshakeAuthExtension($extension));
        $this->assertTrue($manager->isEnabled());

        $this->assertFalse($manager->processClientPostHandshakeAuthExtension(null));
        $this->assertFalse($manager->isEnabled());
    }
}
