# tls-handshake-flow

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)
[![PHP Version Require](https://img.shields.io/packagist/php-v/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)
[![License](https://img.shields.io/packagist/l/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)
[![Build Status](https://img.shields.io/travis/tourze/tls-handshake-flow/master.svg?style=flat-square)](https://travis-ci.org/tourze/tls-handshake-flow)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/tls-handshake-flow.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-handshake-flow)
[![Code Coverage](https://img.shields.io/codecov/c/github/tourze/tls-handshake-flow.svg?style=flat-square)](https://codecov.io/gh/tourze/tls-handshake-flow)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)

A comprehensive TLS handshake flow implementation with state machine support for TLS 1.2 and TLS 1.3.

## Features

- Complete TLS handshake state machine implementation
- Support for TLS 1.2 and TLS 1.3 protocols
- Client and server-side state machines
- Early data (0-RTT) support for TLS 1.3
- Post-handshake authentication management
- Renegotiation handling
- Comprehensive error handling and recovery
- Extensible architecture for custom extensions

## Installation

```bash
composer require tourze/tls-handshake-flow
```

## Usage

This package implements the TLS handshake flow control, including:

- TLS handshake state machine implementation
- Handshake process control
- Handshake stage management
- Error recovery and retry logic
- Renegotiation handling
- Early data (0-RTT) support

### State Machine

The package provides state machine implementations for different TLS versions:

- `TLS12ClientStateMachine` - Client-side state machine for TLS 1.2
- `TLS12ServerStateMachine` - Server-side state machine for TLS 1.2
- `TLS13ClientStateMachine` - Client-side state machine for TLS 1.3
- `TLS13ServerStateMachine` - Server-side state machine for TLS 1.3

Basic usage:

```php
use Tourze\TLSHandshakeFlow\StateMachine\TLS13ClientStateMachine;

// Create a TLS 1.3 client state machine
$stateMachine = new TLS13ClientStateMachine();

// Process a handshake message
$nextState = $stateMachine->getNextState($messageType);
$stateMachine->transitionTo($nextState);

// Check if handshake is completed
if ($stateMachine->isHandshakeCompleted()) {
    // Handshake complete, connection established
}
```

### Early Data (0-RTT) Support

TLS 1.3 supports early data transmission to reduce latency:

```php
use Tourze\TLSHandshakeFlow\Session\EarlyDataManager;

$earlyDataManager = new EarlyDataManager();

// Store early data
$earlyDataId = $earlyDataManager->storeEarlyData($sessionId, $data);

// Retrieve early data
$earlyData = $earlyDataManager->getEarlyData($earlyDataId);
```

### Post-Handshake Authentication

Handle post-handshake authentication for TLS 1.3:

```php
use Tourze\TLSHandshakeFlow\Handshake\PostHandshakeAuthManager;

$authManager = new PostHandshakeAuthManager();

// Initiate post-handshake authentication
$authManager->initiateAuthentication($context);

// Process authentication request
$authManager->processAuthenticationRequest($request);
```

## Requirements

- PHP 8.1 or higher
- OpenSSL extension
- Hash extension
- Ctype extension

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

## Security

If you discover any security-related issues, please email security@example.com instead of using the issue tracker.

## Credits

- [TLS Working Group](https://tools.ietf.org/wg/tls/)
- All contributors

## References

- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 7627 - Extended Master Secret Extension](https://tools.ietf.org/html/rfc7627)
- [RFC 5746 - Renegotiation Indication Extension](https://tools.ietf.org/html/rfc5746)
