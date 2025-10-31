<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeFlow\Tests\StateMachine;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeState;

/**
 * @internal
 */
#[CoversClass(HandshakeState::class)]
final class HandshakeStateTest extends TestCase
{
    public function testStateConstants(): void
    {
        $this->assertSame('INITIAL', HandshakeState::INITIAL);
        $this->assertSame('WAIT_SERVER_HELLO', HandshakeState::WAIT_SERVER_HELLO);
        $this->assertSame('WAIT_CERTIFICATE', HandshakeState::WAIT_CERTIFICATE);
        $this->assertSame('WAIT_SERVER_KEY_EXCHANGE', HandshakeState::WAIT_SERVER_KEY_EXCHANGE);
        $this->assertSame('WAIT_SERVER_HELLO_DONE', HandshakeState::WAIT_SERVER_HELLO_DONE);
        $this->assertSame('WAIT_CLIENT_CERTIFICATE', HandshakeState::WAIT_CLIENT_CERTIFICATE);
        $this->assertSame('WAIT_CLIENT_KEY_EXCHANGE', HandshakeState::WAIT_CLIENT_KEY_EXCHANGE);
        $this->assertSame('WAIT_CERTIFICATE_VERIFY', HandshakeState::WAIT_CERTIFICATE_VERIFY);
        $this->assertSame('WAIT_CHANGE_CIPHER_SPEC', HandshakeState::WAIT_CHANGE_CIPHER_SPEC);
        $this->assertSame('WAIT_FINISHED', HandshakeState::WAIT_FINISHED);
        $this->assertSame('CONNECTED', HandshakeState::CONNECTED);
        $this->assertSame('ERROR', HandshakeState::ERROR);
        $this->assertSame('WAIT_ENCRYPTED_EXTENSIONS', HandshakeState::WAIT_ENCRYPTED_EXTENSIONS);
        $this->assertSame('WAIT_NEW_SESSION_TICKET', HandshakeState::WAIT_NEW_SESSION_TICKET);
    }
}
