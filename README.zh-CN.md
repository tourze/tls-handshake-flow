# tls-handshake-flow

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)
[![PHP Version Require](https://img.shields.io/packagist/php-v/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)
[![License](https://img.shields.io/packagist/l/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)
[![Build Status](https://img.shields.io/travis/tourze/tls-handshake-flow/master.svg?style=flat-square)](https://travis-ci.org/tourze/tls-handshake-flow)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/tls-handshake-flow.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-handshake-flow)
[![Code Coverage](https://img.shields.io/codecov/c/github/tourze/tls-handshake-flow.svg?style=flat-square)](https://codecov.io/gh/tourze/tls-handshake-flow)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-handshake-flow.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-handshake-flow)

全面的 TLS 握手流程实现，支持 TLS 1.2 和 TLS 1.3 的状态机。

## 特性

- 完整的 TLS 握手状态机实现
- 支持 TLS 1.2 和 TLS 1.3 协议
- 客户端和服务端状态机
- TLS 1.3 的早期数据 (0-RTT) 支持
- 握手后认证管理
- 重新协商处理
- 全面的错误处理和恢复
- 支持自定义扩展的可扩展架构

## 安装

```bash
composer require tourze/tls-handshake-flow
```

## 使用方法

本包实现TLS握手流程控制，包括：

- TLS握手状态机实现
- 握手过程控制
- 握手阶段管理
- 错误恢复和重试逻辑
- 处理握手重协商
- 支持早期数据(0-RTT)流程

### 状态机

本包为不同TLS版本提供状态机实现：

- `TLS12ClientStateMachine` - TLS 1.2客户端状态机
- `TLS12ServerStateMachine` - TLS 1.2服务端状态机
- `TLS13ClientStateMachine` - TLS 1.3客户端状态机
- `TLS13ServerStateMachine` - TLS 1.3服务端状态机

基本使用方法：

```php
use Tourze\TLSHandshakeFlow\StateMachine\TLS13ClientStateMachine;

// 创建TLS 1.3客户端状态机
$stateMachine = new TLS13ClientStateMachine();

// 处理握手消息
$nextState = $stateMachine->getNextState($messageType);
$stateMachine->transitionTo($nextState);

// 检查握手是否完成
if ($stateMachine->isHandshakeCompleted()) {
    // 握手完成，连接建立
}
```

### 早期数据(0-RTT)支持

TLS 1.3支持早期数据传输以减少延迟：

```php
use Tourze\TLSHandshakeFlow\Session\EarlyDataManager;

$earlyDataManager = new EarlyDataManager();

// 存储早期数据
$earlyDataId = $earlyDataManager->storeEarlyData($sessionId, $data);

// 获取早期数据
$earlyData = $earlyDataManager->getEarlyData($earlyDataId);
```

### 握手后认证

处理TLS 1.3的握手后认证：

```php
use Tourze\TLSHandshakeFlow\Handshake\PostHandshakeAuthManager;

$authManager = new PostHandshakeAuthManager();

// 发起握手后认证
$authManager->initiateAuthentication($context);

// 处理认证请求
$authManager->processAuthenticationRequest($request);
```

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- Hash 扩展
- Ctype 扩展

## 贡献

请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

## 许可证

MIT 许可证。请查看 [许可证文件](LICENSE) 获取更多信息。

## 安全

如果您发现任何安全相关问题，请发送邮件至 security@example.com，而不是使用问题跟踪器。

## 致谢

- [TLS 工作组](https://tools.ietf.org/wg/tls/)
- 所有贡献者

## 参考文档

- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 7627 - 扩展主密钥扩展](https://tools.ietf.org/html/rfc7627)
- [RFC 5746 - 重新协商指示扩展](https://tools.ietf.org/html/rfc5746)
