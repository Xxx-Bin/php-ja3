# php-ja3

PHP implementation for SSL/TLS JA3 fingerprint and HTTP/2 fingerprint.

This project provides three deployment modes:
1. **Web server integration** ([wkm_ja3.php](#wkm_ja3php) and improved [wkm_ja3_ex.php](#wkm_ja3_exphp))
2. **TCPdump monitoring** ([ja3_tcpdump.php](#ja3_tcpdumpphp))
3. **Standalone HTTP/2 server** ([win/h2_server*.php](#standalone-http2-servers))

## Features

- **TLS Fingerprint**: JA3, JA4 (Client Hello), JA3S (Server Hello)
- **HTTP/2 Fingerprint**: Settings, Window Update, Priority, Pseudo Headers
- **Modular Architecture**: Core protocol and extensions separated
- **PHP 8.2+ Compatible**: No dynamic properties

## Installation

```bash
composer install
```

## Standalone HTTP/2 Servers

New modular HTTP/2 servers with fingerprint support.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │ h2_server.php│  │h2_server_fp. │                        │
│  │   (Basic)    │  │    php       │                        │
│  │              │  │(Fingerprint) │                        │
│  └──────┬───────┘  └──────┬───────┘                        │
└─────────┼─────────────────┼────────────────────────────────┘
          │                 │
          └─────────────────┼───────────────────┐
                            │                   │
┌───────────────────────────▼───────────────────▼─────────────┐
│                     H2Driver                                 │
│              (HTTP/2 Connection Driver)                      │
└───────────────────────────┬─────────────────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
┌─────────▼──────┐ ┌────────▼────────┐ ┌─────▼──────────┐
│ H2Protocol     │ │ H2Fingerprint   │ │   Other        │
│   Parser       │ │   Extension     │ │  Extensions    │
│  (Core)        │ │ (Fingerprint)   │ │                │
└────────────────┘ └─────────────────┘ └────────────────┘
```

See [doc/architecture.md](doc/architecture.md) for detailed architecture documentation.

### h2_server.php (Basic)

Minimal HTTP/2 server without fingerprint collection.

**Run:**
```bash
php win/h2_server.php start
```

### h2_server_fp.php (Fingerprint)

HTTP/2 server with fingerprint collection.

**Features:**
- HTTP/2 fingerprint extraction
- Settings, Window Update, Priority, Pseudo Headers

**Run:**
```bash
php win/h2_server_fp.php start
```

**Response:**
```json
{
    "http2": {
        "fingerprint_str": "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,p,s,a",
        "fingerprint": {
            "S[;]": "1:65536;3:1000;4:6291456;6:262144",
            "WU": 15663105,
            "P[,]": null,
            "PS[,]": ["m", "p", "s", "a"]
        }
    },
    "request": {
        "stream_id": 1,
        "headers": {":method": "GET", ":path": "/", ...},
        "address": "127.0.0.1:12345"
    }
}
```

### HTTP/2 Fingerprint Format

```
SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS

Example:
1:65536;3:1000;4:6291456;6:262144|15663105|0|m,p,s,a
```

- **SETTINGS**: `id:value;id:value;...`
- **WINDOW_UPDATE**: Connection-level window size
- **PRIORITY**: Priority frame info or `0`
- **PSEUDO_HEADERS**: Order of pseudo headers (`m`=`:method`, `p`=`:path`, `s`=`:scheme`, `a`=`:authority`)

## wkm_ja3_ex.php

### Data Flow

```
Browser => php-ja3-ex(INBOUND) => Capture JA3/JA4 + HTTP/2 Fingerprint 
                                    => php-ja3-ex(OUTBOUND) 
                                    => HTTPS Server
```

### Features

- TLS Client Hello fingerprint (JA3, JA4)
- TLS Server Hello fingerprint (JA3S)
- HTTP/2 fingerprint (Settings, Priority, Window Update, Pseudo Headers)

### Configuration

#### 1. Modify TcpConnection.php

```php
// ./vendor/workerman/workerman/Connection/TcpConnection.php line 745

if(defined('STREAM_CRYPTO_METHOD_SERVER')){
    $type = \STREAM_CRYPTO_METHOD_SERVER;
}else{
    $type = \STREAM_CRYPTO_METHOD_SSLv2_SERVER | \STREAM_CRYPTO_METHOD_SSLv23_SERVER;
}
```

#### 2. Set INBOUND/OUTBOUND

```php
// INBOUND - Port for client connections
define('INBOUND','tcp://0.0.0.0:9764');

// OUTBOUND - Backend HTTPS server
define('OUTBOUND','tcp://127.0.0.1:9765');
```

### Run

```bash
php wkm_ja3_ex.php start -d
```

### Test

```bash
curl https://example.com:9764/
```

### Response (JSON)

```json
{
    "tls": {
        "ja3": "hash_value",
        "ja3_str": "771,4865-4866-...",
        "ja4": "t13d1511h2_...",
        "ja4_o": "t13d1511h2_..."
    },
    "tls_server": {
        "ja3s": "hash_value",
        "ja3s_str": "771,4865-..."
    },
    "http2": {
        "fingerprint": "1:65536;3:1000;4:6291456;6:262144|00|0|m,p,s,a",
        "settings": "1:65536;3:1000;4:6291456;6:262144",
        "window_update": "15663105",
        "priority": null,
        "pseudo_headers": "m,p,s,a"
    }
}
```

### Demo

[php-ja3-ex demo](https://bjun.tech/blog/xphp/218#demo_18)

## ja3_tcpdump.php

### Data Flow

```
Browser => nginx(https=>http) => /web/ja3.php
            | |                     A
             V                     | |
           tcpdump => stdout =>  ja3_tcpdump.php
```

### Configuration

#### TCPDUMP_LISTEN_INTERFACE

```php
// tcpdump listen interface, default 1. See 'tcpdump -D' for details
define('TCPDUMP_LISTEN_INTERFACE',1);
```

### Run

```bash
sudo php ja3_tcpdump.php start -d
```

### Test

```bash
curl https://example.com/ja3.php
```

### Response

```json
{"ja3_hash":"0d69ff4……2834766","speed_time":0.402}
```

### Demo and Blog

[php、ja3和tcpdump (TLS握手指纹实践2)](https://bjun.tech/blog/xphp/144#demo_48)

### Known Issues

1. **Return none**: If you visit after a period of time, you may get no response. Close sockets at [chrome://net-internals/#sockets](chrome://net-internals/#sockets)
2. **Slow**: Average time is 0.5~0.6s due to tcpdump command execution

## ja3_tshark.php

Same operation as ja3_tcpdump. Requires tshark version 3.x.

## wkm_ja3.php

### Data Flow

```
Browser => php-ja3(INBOUND) => Capture JA3 
            => php-ja3(OUTBOUND) 
            => nginx(https=>http) 
            => /web/ja3.php
```

### Configuration

#### INBOUND

```php
define('INBOUND','tcp://0.0.0.0:9763');
```

#### OUTBOUND

```php
define('OUTBOUND','tcp://example.com:443');
```

#### Nginx Config

```nginx
server {
    listen :443 ssl;
    server_name example.com;
    # ... ssl settings
    root "pathto/php-ja3/web";
    location ~ \.php(.*)$ {
        # ... php settings
    }
}
```

### Run

```bash
php wkm_ja3.php start -d
```

### Test

```bash
curl https://example.com:9763/ja3.php
```

### Demo

[php-JA3er TLS握手指纹实践](https://bjun.tech/blog/xphp/141#demo_38)

## Project Structure

```
php-ja3/
├── lib/                          # Core library
│   ├── H2CoreInterface.php       # HTTP/2 core interface
│   ├── H2ProtocolParser.php      # HTTP/2 protocol parser
│   ├── H2Driver.php              # HTTP/2 connection driver
│   ├── H2Stream.php              # HTTP/2 stream management
│   ├── H2ExtensionInterface.php  # Extension interface
│   ├── H2ExtensionManager.php    # Extension manager
│   ├── H2FingerprintExtension.php # Fingerprint extension
│   ├── H2ConnectionManager.php   # Connection data manager
│   ├── H2Protocol.php            # Workerman protocol
│   ├── HPACK.php                 # HPACK codec
│   └── ...
├── win/                          # Windows server examples
│   ├── h2_server.php             # Basic HTTP/2 server
│   └── h2_server_fp.php          # Fingerprint server
├── doc/                          # Documentation
│   └── architecture.md           # Architecture documentation
├── web/                          # Web examples
├── wkm_ja3.php                   # Basic proxy mode
├── wkm_ja3_ex.php                # Extended proxy mode
├── ja3_tcpdump.php               # TCPdump mode
└── ja3_tshark.php                # Tshark mode
```

## Update History

- **2024-03-18**: Add JA4 support ([JA4 初探](https://bjun.tech/blog/xphp/246))
- **2025-03-12**: Add HTTP/2 fingerprint support in wkm_ja3_ex.php
- **2025-03-17**: Refactor to modular architecture (core and extensions separated)
- **2025-03-17**: Add PHP 8.2+ compatibility (remove dynamic properties)

## References

- [JA3](https://github.com/salesforce/ja3) - TLS fingerprinting
- [Workerman](https://github.com/walkor/workerman) - PHP async framework

## License

MIT License
