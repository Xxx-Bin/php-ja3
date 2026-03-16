<?php

/**
 * HTTP/2 核心模块接口
 * 
 * 定义 H2 协议核心功能的标准接口
 * 所有核心协议实现必须实现此接口
 */
interface H2CoreInterface
{
    /**
     * HTTP/2 协议常量
     */
    const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    const FRAME_DATA = 0x00;
    const FRAME_HEADERS = 0x01;
    const FRAME_PRIORITY = 0x02;
    const FRAME_RST_STREAM = 0x03;
    const FRAME_SETTINGS = 0x04;
    const FRAME_PUSH_PROMISE = 0x05;
    const FRAME_PING = 0x06;
    const FRAME_GOAWAY = 0x07;
    const FRAME_WINDOW_UPDATE = 0x08;
    const FRAME_CONTINUATION = 0x09;

    const FLAG_END_STREAM = 0x01;
    const FLAG_ACK = 0x01;
    const FLAG_END_HEADERS = 0x04;
    const FLAG_PADDED = 0x08;
    const FLAG_PRIORITY = 0x20;

    const ERROR_NO_ERROR = 0x00;
    const ERROR_PROTOCOL_ERROR = 0x01;
    const ERROR_INTERNAL_ERROR = 0x02;
    const ERROR_FLOW_CONTROL_ERROR = 0x03;
    const ERROR_SETTINGS_TIMEOUT = 0x04;
    const ERROR_STREAM_CLOSED = 0x05;
    const ERROR_FRAME_SIZE_ERROR = 0x06;
    const ERROR_REFUSED_STREAM = 0x07;
    const ERROR_CANCEL = 0x08;
    const ERROR_COMPRESSION_ERROR = 0x09;
    const ERROR_CONNECT_ERROR = 0x0a;
    const ERROR_ENHANCE_YOUR_CALM = 0x0b;
    const ERROR_INADEQUATE_SECURITY = 0x0c;
    const ERROR_HTTP_1_1_REQUIRED = 0x0d;

    const SETTING_HEADER_TABLE_SIZE = 0x01;
    const SETTING_ENABLE_PUSH = 0x02;
    const SETTING_MAX_CONCURRENT_STREAMS = 0x03;
    const SETTING_INITIAL_WINDOW_SIZE = 0x04;
    const SETTING_MAX_FRAME_SIZE = 0x05;
    const SETTING_MAX_HEADER_LIST_SIZE = 0x06;

    /**
     * 解析接收到的数据
     *
     * @param string $data 原始数据
     * @return bool 解析是否成功
     */
    public function parse(string $data): bool;

    /**
     * 设置前导码是否已找到
     *
     * @param bool $found
     * @return void
     */
    public function setPrefaceFound(bool $found): void;

    /**
     * 检查是否是 HTTP/2 连接
     *
     * @return bool
     */
    public function isHttp2(): bool;

    /**
     * 重置解析器状态
     *
     * @return void
     */
    public function reset(): void;

    /**
     * 获取 HPACK 解码器
     *
     * @return HPACK
     */
    public function getHpackDecoder(): HPACK;

    /**
     * 获取 HPACK 编码器
     *
     * @return HPACK
     */
    public function getHpackEncoder(): HPACK;

    /**
     * 注册帧接收回调
     *
     * @param callable $callback function(array $frameInfo): void
     * @return void
     */
    public function onFrame(callable $callback): void;

    /**
     * 注册流数据接收回调
     *
     * @param callable $callback function(int $streamId, string $data, bool $endStream): void
     * @return void
     */
    public function onStreamData(callable $callback): void;

    /**
     * 注册流头部接收回调
     *
     * @param callable $callback function(int $streamId, array $headers, bool $endStream): void
     * @return void
     */
    public function onStreamHeaders(callable $callback): void;

    /**
     * 注册 SETTINGS 帧接收回调
     *
     * @param callable $callback function(array $settings, bool $isAck): void
     * @return void
     */
    public function onSettings(callable $callback): void;

    /**
     * 注册 PRIORITY 帧接收回调
     *
     * @param callable $callback function(int $streamId, int $parentId, int $weight, bool $exclusive): void
     * @return void
     */
    public function onPriority(callable $callback): void;

    /**
     * 注册 WINDOW_UPDATE 帧接收回调
     *
     * @param callable $callback function(int $streamId, int $windowSize): void
     * @return void
     */
    public function onWindowUpdate(callable $callback): void;

    /**
     * 注册 PING 帧接收回调
     *
     * @param callable $callback function(string $data, bool $isAck): void
     * @return void
     */
    public function onPing(callable $callback): void;

    /**
     * 注册 RST_STREAM 帧接收回调
     *
     * @param callable $callback function(int $streamId, int $errorCode): void
     * @return void
     */
    public function onRstStream(callable $callback): void;

    /**
     * 注册 GOAWAY 帧接收回调
     *
     * @param callable $callback function(int $lastStreamId, int $errorCode, string $debugData): void
     * @return void
     */
    public function onGoaway(callable $callback): void;

    /**
     * 创建 DATA 帧
     *
     * @param int $streamId
     * @param string $data
     * @param bool $endStream
     * @return string
     */
    public function createDataFrame(int $streamId, string $data, bool $endStream = false): string;

    /**
     * 创建 HEADERS 帧
     *
     * @param int $streamId
     * @param array $headers
     * @param bool $endStream
     * @param bool $endHeaders
     * @return string
     */
    public function createHeadersFrame(int $streamId, array $headers, bool $endStream = false, bool $endHeaders = true): string;

    /**
     * 创建 SETTINGS 帧
     *
     * @param array $settings
     * @param bool $ack
     * @return string
     */
    public function createSettingsFrame(array $settings, bool $ack = false): string;

    /**
     * 创建 WINDOW_UPDATE 帧
     *
     * @param int $streamId
     * @param int $increment
     * @return string
     */
    public function createWindowUpdateFrame(int $streamId, int $increment): string;

    /**
     * 创建 RST_STREAM 帧
     *
     * @param int $streamId
     * @param int $errorCode
     * @return string
     */
    public function createRstStreamFrame(int $streamId, int $errorCode): string;

    /**
     * 创建 GOAWAY 帧
     *
     * @param int $lastStreamId
     * @param int $errorCode
     * @param string $debugData
     * @return string
     */
    public function createGoawayFrame(int $lastStreamId, int $errorCode, string $debugData = ''): string;

    /**
     * 创建 PRIORITY 帧
     *
     * @param int $streamId
     * @param int $parentId
     * @param int $weight
     * @param bool $exclusive
     * @return string
     */
    public function createPriorityFrame(int $streamId, int $parentId, int $weight, bool $exclusive = false): string;

    /**
     * 创建 CONTINUATION 帧
     *
     * @param int $streamId
     * @param array $headers
     * @param bool $endHeaders
     * @return string
     */
    public function createContinuationFrame(int $streamId, array $headers, bool $endHeaders = true): string;

    /**
     * 创建 PING 帧
     *
     * @param string|null $data
     * @param bool $ack
     * @return string|null
     */
    public function createPingFrame(?string $data = null, bool $ack = false): ?string;

    /**
     * 获取流数据
     *
     * @param int $streamId
     * @return string|null
     */
    public function getStreamData(int $streamId): ?string;

    /**
     * 获取流头部
     *
     * @param int $streamId
     * @return array|null
     */
    public function getStreamHeaders(int $streamId): ?array;

    /**
     * 获取所有流
     *
     * @return array
     */
    public function getAllStreams(): array;

    /**
     * 获取帧类型名称
     *
     * @param int $type
     * @return string
     */
    public static function getFrameTypeName(int $type): string;

    /**
     * 获取错误名称
     *
     * @param int $errorCode
     * @return string
     */
    public static function getErrorName(int $errorCode): string;

    /**
     * 获取设置名称
     *
     * @param int $settingId
     * @return string
     */
    public static function getSettingName(int $settingId): string;
}
