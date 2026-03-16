# HTTP/2 指纹采集系统架构文档

## 概述

本项目实现了基于 PHP 的 HTTP/2 指纹采集系统，采用模块化架构设计，核心协议解析与扩展功能分离。

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层 (Application)                    │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │ h2_server.php│  │h2_server_fp. │                        │
│  │   (基础版)   │  │    php       │                        │
│  │              │  │  (指纹版)    │                        │
│  └──────┬───────┘  └──────┬───────┘                        │
└─────────┼─────────────────┼────────────────────────────────┘
          │                 │
          └─────────────────┼───────────────────┐
                            │                   │
┌───────────────────────────▼───────────────────▼─────────────┐
│                    H2ConnectionManager                       │
│              (连接数据管理，避免动态属性)                     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     H2Driver (驱动层)                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  - 协议状态管理 (STATE_IDLE/OPEN/CLOSING/CLOSED)      │  │
│  │  - 流管理 (H2Stream)                                 │  │
│  │  - 帧处理 (HEADERS, DATA, SETTINGS, etc.)            │  │
│  │  - 请求/响应处理                                     │  │
│  └──────────────────────┬───────────────────────────────┘  │
└─────────────────────────┼───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
┌─────────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
│  H2Protocol    │ │ H2Extension │ │   H2Core    │
│    Parser      │ │   Manager   │ │  Interface  │
│   (核心协议)    │ │  (扩展管理)  │ │  (接口定义) │
└────────┬───────┘ └──────┬──────┘ └─────────────┘
         │                │
         │    ┌───────────┘
         │    │
┌────────▼────▼──┐ ┌──────────────┐
│H2Fingerprint   │ │   其他扩展    │
│  Extension     │ │              │
│  (指纹采集)     │ │              │
└────────────────┘ └──────────────┘
```

## 核心组件

### 1. H2CoreInterface (lib/H2CoreInterface.php)

定义了 HTTP/2 核心协议接口，包括：
- 帧类型常量 (HEADERS, DATA, SETTINGS, etc.)
- 错误码常量
- 设置项常量
- 回调注册方法 (onFrame, onStreamHeaders, onSettings, etc.)
- 帧创建方法 (createHeadersFrame, createDataFrame, etc.)

### 2. H2ProtocolParser (lib/H2ProtocolParser.php)

HTTP/2 协议解析器，实现 H2CoreInterface：
- 帧解析 (parseFrame)
- HPACK 头部解码
- 回调触发机制
- 连接状态管理

### 3. H2Driver (lib/H2Driver.php)

HTTP/2 连接驱动器：
- 管理连接生命周期
- 处理输入数据流
- 管理 HTTP/2 流 (H2Stream)
- 协调扩展回调执行顺序
- 发送请求/响应

### 4. H2ExtensionInterface (lib/H2ExtensionInterface.php)

扩展接口定义：
- 扩展名称和版本
- 初始化和启用/禁用
- 重置状态
- 配置管理

### 5. H2ExtensionManager (lib/H2ExtensionManager.php)

扩展管理器：
- 注册/注销扩展
- 启用/禁用扩展
- 初始化所有扩展
- 重置所有扩展状态

### 6. H2ConnectionManager (lib/H2ConnectionManager.php)

连接数据管理器（PHP 8.2+ 兼容）：
- 使用静态数组存储连接数据
- 避免动态属性废弃警告
- 管理 H2Driver 实例

## 扩展模块

### H2FingerprintExtension (lib/H2FingerprintExtension.php)

HTTP/2 指纹采集扩展：

**采集的数据：**
- Settings 帧参数 (S)
- Window Update 值 (WU)
- Priority 帧信息 (P)
- 伪头部顺序 (PS)

**配置选项：**
```php
[
    'extract_settings' => true,           // 提取 SETTINGS
    'extract_window_update' => true,      // 提取 WINDOW_UPDATE
    'extract_priority' => true,           // 提取 PRIORITY
    'extract_window_update_frames' => false, // 提取每个 WU 帧
    'extract_priority_frames' => false,   // 提取每个 PRIORITY 帧
    'extract_pseudo_headers' => true,     // 提取伪头部
]
```

**指纹格式：**
```
1:65536;3:1000;4:6291456;6:262144|15663105|0|m,p,s,a
SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS
```

## 数据流

### HTTP/2 连接建立流程

```
1. TCP 连接建立
   ↓
2. TLS 握手 (ALPN 协商 h2)
   ↓
3. 客户端发送 HTTP/2 前导码 (PRI * HTTP/2.0)
   ↓
4. 服务器发送 SETTINGS 帧
   ↓
5. 客户端发送 SETTINGS 帧
   ↓
6. 双方发送 SETTINGS ACK
   ↓
7. 连接就绪 (STATE_OPEN)
```

### 指纹采集流程

```
1. 收到客户端 SETTINGS 帧
   ↓
2. H2FingerprintExtension::onSettings()
   ↓
3. 提取 Settings 参数，存储到 h2fp['S[;]']
   ↓
4. 收到 WINDOW_UPDATE 帧
   ↓
5. H2FingerprintExtension::onWindowUpdate()
   ↓
6. 提取窗口大小，存储到 h2fp['WU']
   ↓
7. 收到 HEADERS 帧
   ↓
8. H2FingerprintExtension::onStreamHeaders()
   ↓
9. 提取伪头部顺序，存储到 h2fp['PS[,]']
   ↓
10. 指纹完成，标记 isComplete = true
```

## 回调执行顺序

为了确保扩展先于 H2Driver 处理数据，回调注册顺序如下：

```
1. 创建 H2Driver (构造函数不注册回调)
2. 注册扩展到 ExtensionManager
3. 启用扩展
4. ExtensionManager::initializeAll()
   - 扩展注册回调到 Core (onSettings, onStreamHeaders, etc.)
5. H2Driver::initialize()
   - H2Driver 注册回调到 Core
6. 当帧到达时：
   - 先执行扩展回调 (先注册)
   - 后执行 H2Driver 回调 (后注册)
```

## 服务器示例

### 基础版 (h2_server.php)

仅支持 HTTP/2 协议，无指纹采集：
```php
$driver = new H2Driver($core, $extensionManager);
H2ConnectionManager::setDriver($connection, $driver);
$driver->onRequest(function($streamId, $headers, $data) {
    // 处理请求
});
```

### 指纹版 (h2_server_fp.php)

支持 HTTP/2 指纹采集：
```php
$fingerprintExt = new H2FingerprintExtension();
$extensionManager->register($fingerprintExt);
$extensionManager->enableExtension('h2_fingerprint');
// ...
$h2Fingerprint = $fingerprintExt->getFingerprintString();
```

## PHP 8.2+ 兼容性

为避免动态属性废弃警告，使用以下方案：

### H2Protocol.php
```php
private static $connectionProtocols = [];

public static function setConnectionProtocol($connection, $protocol) {
    $connectionId = spl_object_id($connection);
    self::$connectionProtocols[$connectionId] = $protocol;
}
```

### H2ConnectionManager.php
```php
private static $drivers = [];

public static function setDriver($connection, $driver) {
    $connectionId = spl_object_id($connection);
    self::$drivers[$connectionId] = $driver;
}
```

## 文件清单

### 核心文件
- `lib/H2CoreInterface.php` - 核心接口定义
- `lib/H2ProtocolParser.php` - 协议解析器
- `lib/H2Driver.php` - 连接驱动器
- `lib/H2Stream.php` - 流管理
- `lib/HPACK.php` - HPACK 编解码

### 扩展文件
- `lib/H2ExtensionInterface.php` - 扩展接口
- `lib/H2ExtensionManager.php` - 扩展管理器
- `lib/H2FingerprintExtension.php` - 指纹采集扩展

### 工具文件
- `lib/H2ConnectionManager.php` - 连接数据管理
- `lib/H2Protocol.php` - Workerman 协议实现

### 服务器示例
- `win/h2_server.php` - 基础 HTTP/2 服务器
- `win/h2_server_fp.php` - 指纹采集服务器

## 更新日志

- **2025-03-12**: 添加 HTTP/2 指纹采集支持
- **2025-03-17**: 重构为模块化架构，核心与扩展分离
- **2025-03-17**: 添加 PHP 8.2+ 兼容性支持（移除动态属性）
