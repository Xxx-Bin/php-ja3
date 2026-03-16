<?php

namespace Workerman\Protocols;

require_once __DIR__ . '/H2Driver.php';

/**
 * HTTP/2 Protocol for Workerman
 *
 * 实现 Workerman 的 ProtocolInterface
 * 用于处理 HTTP/2 连接和帧数据
 * 支持 HTTP/1.1 回退
 *
 * 设计原则：
 * 1. HTTP/1.1: 按请求分割，返回完整请求
 * 2. HTTP/2: 按帧分割，但将所有帧数据传递给 H2Driver 处理
 */
class H2
{
    /**
     * HTTP/2 连接前导码
     */
    const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    /**
     * 存储连接协议类型的静态数组
     * 避免使用动态属性（PHP 8.2+ 废弃）
     * @var array<int, string>
     */
    private static $connectionProtocols = [];

    /**
     * 获取连接的协议类型
     *
     * @param TcpConnection $connection 连接对象
     * @return string|null 协议类型，如果没有设置则返回 null
     */
    private static function getConnectionProtocol($connection): ?string
    {
        $connectionId = spl_object_id($connection);
        return self::$connectionProtocols[$connectionId] ?? null;
    }

    /**
     * 设置连接的协议类型
     *
     * @param TcpConnection $connection 连接对象
     * @param string $protocol 协议类型
     * @return void
     */
    private static function setConnectionProtocol($connection, string $protocol): void
    {
        $connectionId = spl_object_id($connection);
        self::$connectionProtocols[$connectionId] = $protocol;
    }

    /**
     * 移除连接的协议类型（连接关闭时调用）
     *
     * @param TcpConnection $connection 连接对象
     * @return void
     */
    public static function removeConnectionProtocol($connection): void
    {
        $connectionId = spl_object_id($connection);
        unset(self::$connectionProtocols[$connectionId]);
    }

    /**
     * 检查包是否完整
     *
     * @param string $buffer 接收到的数据
     * @param TcpConnection $connection 连接对象
     * @return int 包长度，0 表示数据不完整，-1 表示出错
     */
    public static function input($buffer, $connection)
    {
        $protocol = self::getConnectionProtocol($connection);

        // 检查是否是 HTTP/2 连接
        if ($protocol === null) {
            $prefaceLen = strlen(self::PREFACE);

            // 数据不够判断协议类型
            if (strlen($buffer) < 16) {
                // 检查是否是 HTTP/1.1 请求
                if (strpos($buffer, "GET ") === 0 ||
                    strpos($buffer, "POST ") === 0 ||
                    strpos($buffer, "HEAD ") === 0 ||
                    strpos($buffer, "PUT ") === 0 ||
                    strpos($buffer, "DELETE ") === 0 ||
                    strpos($buffer, "OPTIONS ") === 0 ||
                    strpos($buffer, "PATCH ") === 0 ||
                    strpos($buffer, "HTTP/1.") !== false) {
                    self::setConnectionProtocol($connection, 'http/1.1');
                    return self::inputHttp1($buffer, $connection);
                }
                return 0; // 等待更多数据
            }

            // 判断协议类型
            if (strpos($buffer, self::PREFACE) === 0) {
                self::setConnectionProtocol($connection, 'http/2');
                // 对于 HTTP/2，返回前导码长度，让 decode 处理
                return $prefaceLen;
            } else {
                self::setConnectionProtocol($connection, 'http/1.1');
                return self::inputHttp1($buffer, $connection);
            }
        }

        // 根据协议类型处理
        if ($protocol === 'http/2') {
            return self::inputHttp2($buffer, $connection);
        } else {
            return self::inputHttp1($buffer, $connection);
        }
    }

    /**
     * 处理 HTTP/1.1 输入
     */
    private static function inputHttp1($buffer, $connection)
    {
        // 查找 HTTP 头结束标记
        $pos = strpos($buffer, "\r\n\r\n");
        if ($pos === false) {
            // 检查是否是有效的 HTTP 请求
            if (strlen($buffer) > 8192) {
                return -1; // 请求头太大
            }
            return 0; // 等待更多数据
        }

        // 解析 Content-Length
        $headerLen = $pos + 4;
        $bodyLen = 0;
        
        if (preg_match('/Content-Length:\s*(\d+)/i', $buffer, $matches)) {
            $bodyLen = intval($matches[1]);
        }

        $totalLen = $headerLen + $bodyLen;
        if (strlen($buffer) < $totalLen) {
            return 0; // 等待更多数据
        }

        return $totalLen;
    }

    /**
     * 处理 HTTP/2 输入
     * 
     * HTTP/2 是帧协议，每次返回一个完整帧的长度
     * 让 H2Driver 来处理帧的组装和请求解析
     */
    private static function inputHttp2($buffer, $connection)
    {
        // 解析帧头（9 字节）
        if (strlen($buffer) < 9) {
            return 0;
        }

        $header = substr($buffer, 0, 9);
        $parsed = unpack('Clength3/Clength2/Clength1/Ctype/Cflags/Nid', $header);
        $frameLength = ($parsed['length3'] << 16) | ($parsed['length2'] << 8) | $parsed['length1'];

        // 检查帧数据是否完整
        $totalLength = 9 + $frameLength;
        if (strlen($buffer) < $totalLength) {
            return 0;
        }

        return $totalLength;
    }

    /**
     * 解码数据
     *
     * @param string $buffer 接收到的数据
     * @param TcpConnection $connection 连接对象
     * @return array|false 解码后的数据，false 表示解码失败
     */
    public static function decode($buffer, $connection)
    {
        // 确定协议类型
        $protocol = self::getConnectionProtocol($connection);
        if ($protocol === null) {
            $protocol = (strpos($buffer, self::PREFACE) === 0) ? 'http/2' : 'http/1.1';
            self::setConnectionProtocol($connection, $protocol);
        }

        if ($protocol === 'http/2') {
            return self::decodeHttp2($buffer, $connection);
        } else {
            return self::decodeHttp1($buffer, $connection);
        }
    }

    /**
     * 解码 HTTP/1.1 请求
     */
    private static function decodeHttp1($buffer, $connection)
    {
        $pos = strpos($buffer, "\r\n\r\n");
        if ($pos === false) {
            return false;
        }

        $headerStr = substr($buffer, 0, $pos);
        $body = substr($buffer, $pos + 4);

        // 解析请求行
        $lines = explode("\r\n", $headerStr);
        $requestLine = array_shift($lines);
        
        if (!preg_match('/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP\/(\d\.\d)$/', $requestLine, $matches)) {
            return false;
        }

        $method = $matches[1];
        $uri = $matches[2];
        $version = $matches[3];

        // 解析头部
        $headers = [];
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                list($name, $value) = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        return [
            'protocol' => 'http/1.1',
            'method' => $method,
            'uri' => $uri,
            'version' => $version,
            'headers' => $headers,
            'body' => $body,
            'raw' => $buffer,
        ];
    }

    /**
     * 解码 HTTP/2 帧
     * 
     * 将原始帧数据传递给 H2Driver 处理
     */
    private static function decodeHttp2($buffer, $connection)
    {
        // 检查是否是前导码
        $preface = self::PREFACE;
        if (strpos($buffer, $preface) === 0 && strlen($buffer) === strlen($preface)) {
            return [
                'protocol' => 'http/2',
                'type' => 'preface',
                'raw' => $buffer,
            ];
        }

        if (strlen($buffer) < 9) {
            return false;
        }

        // 解析帧头
        $header = substr($buffer, 0, 9);
        $parsed = unpack('Clength3/Clength2/Clength1/Ctype/Cflags/Nid', $header);

        $frameLength = ($parsed['length3'] << 16) | ($parsed['length2'] << 8) | $parsed['length1'];
        $frameType = $parsed['type'];
        $frameFlags = $parsed['flags'];
        $streamId = $parsed['id'] & 0x7fffffff;

        // 返回帧信息，包含原始数据供 H2Driver 处理
        return [
            'protocol' => 'http/2',
            'type' => $frameType,
            'flags' => $frameFlags,
            'streamId' => $streamId,
            'length' => $frameLength,
            'data' => substr($buffer, 9, $frameLength),
            'raw' => $buffer,
            'isFrame' => true,
        ];
    }

    /**
     * 编码数据
     *
     * @param array|string $data 要编码的数据
     * @param TcpConnection $connection 连接对象
     * @return string 编码后的数据
     */
    public static function encode($data, $connection)
    {
        if (is_string($data)) {
            return $data;
        }

        if (!is_array($data)) {
            return '';
        }

        // 根据协议类型编码
        $protocol = $data['protocol'] ?? (self::getConnectionProtocol($connection) ?? 'http/1.1');

        if ($protocol === 'http/1.1') {
            return self::encodeHttp1($data, $connection);
        } else {
            return self::encodeHttp2($data, $connection);
        }
    }

    /**
     * 编码 HTTP/1.1 响应
     */
    private static function encodeHttp1($data, $connection)
    {
        $status = $data['status'] ?? 200;
        $statusText = $data['statusText'] ?? 'OK';
        $headers = $data['headers'] ?? [];
        $body = $data['body'] ?? '';

        // 构建响应
        $response = "HTTP/1.1 $status $statusText\r\n";
        $response .= "Server: workerman/h2\r\n";
        $response .= "Connection: keep-alive\r\n";
        
        // 添加 Content-Length 如果没有
        if (!isset($headers['content-length']) && !isset($headers['Content-Length'])) {
            $headers['Content-Length'] = strlen($body);
        }

        foreach ($headers as $name => $value) {
            $response .= "$name: $value\r\n";
        }
        $response .= "\r\n";
        $response .= $body;

        return $response;
    }

    /**
     * 编码 HTTP/2 帧
     */
    private static function encodeHttp2($data, $connection)
    {
        $type = $data['type'] ?? 0;
        $flags = $data['flags'] ?? 0;
        $streamId = $data['streamId'] ?? 0;
        $payload = $data['data'] ?? '';

        $length = strlen($payload);

        // 构建帧头
        $frame = pack('C', ($length >> 16) & 0xFF);
        $frame .= pack('C', ($length >> 8) & 0xFF);
        $frame .= pack('C', $length & 0xFF);
        $frame .= pack('C', $type);
        $frame .= pack('C', $flags);
        $frame .= pack('N', $streamId & 0x7fffffff);
        $frame .= $payload;

        return $frame;
    }

    /**
     * 获取协议名称
     * 
     * @return string
     */
    public static function getName()
    {
        return 'h2';
    }
}
