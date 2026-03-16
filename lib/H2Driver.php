<?php

require_once __DIR__ . '/H2CoreInterface.php';
require_once __DIR__ . '/H2ExtensionInterface.php';
require_once __DIR__ . '/H2ExtensionManager.php';
require_once __DIR__ . '/H2Stream.php';

/**
 * HTTP/2 驱动 - 核心协议实现
 * 
 * 使用依赖注入模式，支持扩展模块的灵活添加/移除
 */
class H2Driver
{
    const STATE_IDLE = 'idle';
    const STATE_WAITING_PREFACE = 'waiting_preface';
    const STATE_WAITING_SETTINGS = 'waiting_settings';
    const STATE_HANDSHAKE_COMPLETE = 'handshake_complete';
    const STATE_ESTABLISHED = 'established';
    const STATE_CLOSING = 'closing';
    const STATE_CLOSED = 'closed';

    const DEFAULT_WINDOW_SIZE = 65535;
    const MAX_FRAME_SIZE = 16384;

    private $state = self::STATE_IDLE;
    private $buffer = '';
    private $streams = [];
    private $nextStreamId = 1;
    private $lastStreamId = 0;

    private $localSettings = [];
    private $remoteSettings = [];
    private $localWindowSize;
    private $remoteWindowSize;

    private $hpackDecoder;
    private $hpackEncoder;

    private $requestCallback = null;
    private $responseCallback = null;
    private $errorCallback = null;
    private $closeCallback = null;

    private $sendCallback = null;
    private $closeConnectionCallback = null;

    private $isServer = false;
    private $prefaceReceived = false;
    private $settingsReceived = false;
    private $settingsAckReceived = false;

    private $pendingResponses = [];
    private $goawaySent = false;
    private $goawayReceived = false;

    /**
     * 流最后活动时间 [streamId => timestamp]
     * @var array<int, float>
     */
    private $streamLastActivity = [];

    /**
     * 流超时时间（秒）
     */
    private const STREAM_TIMEOUT = 60;

    /**
     * 上次清理时间
     */
    private $lastCleanupTime = 0;

    /**
     * 清理间隔（秒）
     */
    private const CLEANUP_INTERVAL = 30;

    /**
     * 核心协议解析器
     * @var H2CoreInterface
     */
    private $core;

    /**
     * 扩展管理器
     * @var H2ExtensionManagerInterface
     */
    private $extensionManager;

    /**
     * 构造函数
     *
     * @param H2CoreInterface|null $core 核心协议模块，null 则使用默认 H2ProtocolParser
     * @param H2ExtensionManagerInterface|null $extensionManager 扩展管理器，null 则创建默认
     */
    public function __construct(?H2CoreInterface $core = null, ?H2ExtensionManagerInterface $extensionManager = null)
    {
        $this->core = $core ?? new H2ProtocolParser();
        $this->extensionManager = $extensionManager ?? new H2ExtensionManager();

        $this->hpackDecoder = $this->core->getHpackDecoder();
        $this->hpackEncoder = $this->core->getHpackEncoder();

        $this->initializeLocalSettings();
        // 注意：不在构造函数中注册回调，而是在 initialize() 中注册
        // 这样扩展可以先注册回调，H2Driver 后注册，确保扩展先执行
    }

    /**
     * 初始化本地设置
     */
    private function initializeLocalSettings(): void
    {
        $this->localSettings = [
            H2CoreInterface::SETTING_HEADER_TABLE_SIZE => 4096,
            H2CoreInterface::SETTING_ENABLE_PUSH => 0,
            H2CoreInterface::SETTING_MAX_CONCURRENT_STREAMS => 100,
            H2CoreInterface::SETTING_INITIAL_WINDOW_SIZE => self::DEFAULT_WINDOW_SIZE,
            H2CoreInterface::SETTING_MAX_FRAME_SIZE => self::MAX_FRAME_SIZE,
        ];
        $this->localWindowSize = self::DEFAULT_WINDOW_SIZE;
        $this->remoteWindowSize = self::DEFAULT_WINDOW_SIZE;
    }

    /**
     * 设置核心回调
     */
    private function setupCoreCallbacks(): void
    {
        $this->core->onFrame([$this, 'onFrame']);
        $this->core->onStreamData([$this, 'onStreamData']);
        $this->core->onStreamHeaders([$this, 'onStreamHeaders']);
        $this->core->onSettings([$this, 'onSettings']);
        $this->core->onPriority([$this, 'onPriority']);
        $this->core->onWindowUpdate([$this, 'onWindowUpdate']);
        $this->core->onPing([$this, 'onPing']);
        $this->core->onRstStream([$this, 'onRstStream']);
        $this->core->onGoaway([$this, 'onGoaway']);
    }

    /**
     * 初始化 H2Driver
     * 在扩展初始化完成后调用，确保扩展回调先于 H2Driver 回调执行
     */
    public function initialize(): void
    {
        $this->setupCoreCallbacks();
    }

    /**
     * 获取核心协议模块
     *
     * @return H2CoreInterface
     */
    public function getCore(): H2CoreInterface
    {
        return $this->core;
    }

    /**
     * 获取扩展管理器
     *
     * @return H2ExtensionManagerInterface
     */
    public function getExtensionManager(): H2ExtensionManagerInterface
    {
        return $this->extensionManager;
    }

    /**
     * 注册扩展
     *
     * @param H2ExtensionInterface $extension
     * @return void
     */
    public function registerExtension(H2ExtensionInterface $extension): void
    {
        $this->extensionManager->register($extension);
    }

    /**
     * 启用扩展
     *
     * @param string $name
     * @return void
     */
    public function enableExtension(string $name): void
    {
        $this->extensionManager->enableExtension($name);
        $this->extensionManager->initializeAll($this->core);
    }

    /**
     * 禁用扩展
     *
     * @param string $name
     * @return void
     */
    public function disableExtension(string $name): void
    {
        $this->extensionManager->disableExtension($name);
    }

    /**
     * 获取扩展
     *
     * @param string $name
     * @return H2ExtensionInterface|null
     */
    public function getExtension(string $name): ?H2ExtensionInterface
    {
        return $this->extensionManager->getExtension($name);
    }

    public function onFrame(array $frameInfo): void
    {
        // 核心帧处理
    }

    public function onStreamData(int $streamId, string $data, bool $endStream): void
    {
        if (!isset($this->streams[$streamId])) {
            return;
        }

        // 更新流活动时间
        $this->streamLastActivity[$streamId] = microtime(true);

        $stream = $this->streams[$streamId];
        $stream->appendData($data);

        if ($endStream) {
            $stream->closeRemote();
            $this->handleRequest($streamId);
        }

        // 定期清理过期流
        $this->cleanupStaleStreams();
    }

    public function onStreamHeaders(int $streamId, array $headers, bool $endStream): void
    {
        if (!isset($this->streams[$streamId])) {
            $this->streams[$streamId] = new H2Stream($streamId);
        }

        // 更新流活动时间
        $this->streamLastActivity[$streamId] = microtime(true);

        $stream = $this->streams[$streamId];
        $stream->setHeaders($headers);

        if ($stream->getState() === H2Stream::STATE_IDLE) {
            $stream->open();
        }

        // 如果 HEADERS 帧标记了 END_STREAM，立即处理请求
        if ($endStream) {
            $stream->closeRemote();
            $this->handleRequest($streamId);
        }
    }

    public function onSettings(array $settings, bool $isAck): void
    {
        if ($isAck) {
            $this->settingsAckReceived = true;
            return;
        }

        $this->settingsReceived = true;

        foreach ($settings as $key => $value) {
            $this->remoteSettings[$key] = $value;

            switch ($key) {
                case H2CoreInterface::SETTING_HEADER_TABLE_SIZE:
                    $this->hpackEncoder->setMaxDynamicTableSize($value);
                    break;
                case H2CoreInterface::SETTING_INITIAL_WINDOW_SIZE:
                    $this->remoteWindowSize = $value;
                    break;
            }
        }

        $this->sendSettingsAck();
    }

    public function onPriority(int $streamId, int $parentId, int $weight, bool $exclusive): void
    {
        if (!isset($this->streams[$streamId])) {
            $this->streams[$streamId] = new H2Stream($streamId);
        }

        $stream = $this->streams[$streamId];
        $stream->setPriority($parentId, $weight, $exclusive);
    }

    public function onWindowUpdate(int $streamId, int $windowSize): void
    {
        if ($streamId === 0) {
            $this->remoteWindowSize += $windowSize;
        } elseif (isset($this->streams[$streamId])) {
            $this->streams[$streamId]->updateWindowSize($windowSize);
        }
    }

    public function onPing(string $data, bool $isAck): void
    {
        if (!$isAck) {
            // 自动响应 PING
            $this->sendPingAck($data);
        }
    }

    public function onRstStream(int $streamId, int $errorCode): void
    {
        if (isset($this->streams[$streamId])) {
            $this->streams[$streamId]->reset($errorCode);
        }
    }

    public function onGoaway(int $lastStreamId, int $errorCode, string $debugData): void
    {
        $this->goawayReceived = true;
        $this->state = self::STATE_CLOSING;

        if ($this->errorCallback) {
            call_user_func($this->errorCallback, 'goaway_received', $errorCode, $debugData);
        }
    }

    public function setServerMode(bool $isServer = true): void
    {
        $this->isServer = $isServer;
    }

    public function handleInput(string $data): void
    {
        $this->buffer .= $data;

        if (!$this->isServer) {
            return;
        }

        if (!$this->prefaceReceived) {
            if (strpos($this->buffer, H2CoreInterface::PREFACE) === 0) {
                $this->prefaceReceived = true;
                $this->state = self::STATE_WAITING_SETTINGS;
                $this->buffer = substr($this->buffer, strlen(H2CoreInterface::PREFACE));
                // 告诉 core 前导码已找到，这样它就不会检查前导码了
                $this->core->setPrefaceFound(true);
                $this->sendServerPreface();
            } else {
                if (strlen($this->buffer) > 100) {
                    $this->handleError('invalid_preface');
                }
                return;
            }
        }

        // 解析 buffer 中的数据（前导码已被移除）
        $this->core->parse($this->buffer);
        // 清空 buffer，因为数据已经传递给 core
        $this->buffer = '';
    }

    private function sendServerPreface(): void
    {
        $settingsFrame = $this->core->createSettingsFrame($this->localSettings);
        $this->send($settingsFrame);
    }

    private function sendSettingsAck(): void
    {
        $ackFrame = $this->core->createSettingsFrame([], true);
        $this->send($ackFrame);
    }

    private function sendPingAck(string $data): void
    {
        $pingFrame = $this->core->createPingFrame($data, true);
        $this->send($pingFrame);
    }

    public function sendRequest(array $headers, string $body = ''): int
    {
        $streamId = $this->nextStreamId;
        $this->nextStreamId += 2;

        $stream = new H2Stream($streamId);
        $this->streams[$streamId] = $stream;
        $stream->open();

        $hasBody = strlen($body) > 0;

        $headersFrame = $this->core->createHeadersFrame($streamId, $headers, !$hasBody, true);
        $this->send($headersFrame);

        if ($hasBody) {
            $this->sendData($streamId, $body, true);
        }

        return $streamId;
    }

    public function sendResponse(int $streamId, int $status, array $headers = [], string $body = ''): void
    {
        if (!isset($this->streams[$streamId])) {
            return;
        }

        $responseHeaders = [':status' => (string)$status];
        $responseHeaders = array_merge($responseHeaders, $headers);

        $hasBody = strlen($body) > 0;

        $headersFrame = $this->core->createHeadersFrame($streamId, $responseHeaders, !$hasBody, true);
        $this->send($headersFrame);

        if ($hasBody) {
            $this->sendData($streamId, $body, true);
        }
    }

    public function sendData(int $streamId, string $data, bool $endStream = false): void
    {
        if (!isset($this->streams[$streamId])) {
            return;
        }

        $stream = $this->streams[$streamId];
        $chunkSize = min(strlen($data), $this->localSettings[H2CoreInterface::SETTING_MAX_FRAME_SIZE] ?? self::MAX_FRAME_SIZE);

        while (strlen($data) > 0) {
            $chunk = substr($data, 0, $chunkSize);
            $data = substr($data, $chunkSize);

            $isLastChunk = empty($data) && $endStream;
            $dataFrame = $this->core->createDataFrame($streamId, $chunk, $isLastChunk);
            $this->send($dataFrame);

            $stream->sendData($chunk, $isLastChunk);
        }
    }

    public function sendGoaway(int $errorCode = H2CoreInterface::ERROR_NO_ERROR, string $debugData = ''): void
    {
        if ($this->goawaySent) {
            return;
        }

        $lastStreamId = $this->lastStreamId;
        $goawayFrame = $this->core->createGoawayFrame($lastStreamId, $errorCode, $debugData);
        $this->send($goawayFrame);

        $this->goawaySent = true;
        $this->state = self::STATE_CLOSING;
    }

    public function closeStream(int $streamId): void
    {
        if (!isset($this->streams[$streamId])) {
            return;
        }

        $stream = $this->streams[$streamId];
        $stream->closeLocal();

        if ($stream->isClosed()) {
            unset($this->streams[$streamId]);
            unset($this->streamLastActivity[$streamId]);
        }
    }

    /**
     * 清理过期的流
     * 防止内存泄漏，定期关闭长时间不活动的流
     */
    private function cleanupStaleStreams(): void
    {
        $now = microtime(true);

        // 检查是否需要清理
        if ($now - $this->lastCleanupTime < self::CLEANUP_INTERVAL) {
            return;
        }

        $this->lastCleanupTime = $now;
        $timeout = self::STREAM_TIMEOUT;

        foreach ($this->streamLastActivity as $streamId => $lastActivity) {
            if ($now - $lastActivity > $timeout) {
                // 流超时，强制关闭
                if (isset($this->streams[$streamId])) {
                    $stream = $this->streams[$streamId];
                    if (!$stream->isClosed()) {
                        $this->resetStream($streamId, H2CoreInterface::ERROR_CANCEL);
                    }
                    unset($this->streams[$streamId]);
                }
                unset($this->streamLastActivity[$streamId]);
            }
        }
    }

    public function resetStream(int $streamId, int $errorCode = H2CoreInterface::ERROR_CANCEL): void
    {
        if (!isset($this->streams[$streamId])) {
            return;
        }

        $rstFrame = $this->core->createRstStreamFrame($streamId, $errorCode);
        $this->send($rstFrame);

        $this->streams[$streamId]->reset($errorCode);
    }

    private function send(string $data): void
    {
        if ($this->sendCallback) {
            call_user_func($this->sendCallback, $data);
        }
    }

    private function handleRequest(int $streamId): void
    {
        if (!isset($this->streams[$streamId])) {
            return;
        }

        $stream = $this->streams[$streamId];
        $headers = $stream->getHeaders();
        $body = $stream->getData();

        if ($this->requestCallback) {
            call_user_func($this->requestCallback, $streamId, $headers, $body);
        }
    }

    private function handleError(string $error): void
    {
        if ($this->errorCallback) {
            call_user_func($this->errorCallback, $error);
        }
        $this->close();
    }

    public function onRequest(callable $callback): void
    {
        $this->requestCallback = $callback;
    }

    public function onResponse(callable $callback): void
    {
        $this->responseCallback = $callback;
    }

    public function onError(callable $callback): void
    {
        $this->errorCallback = $callback;
    }

    public function onClose(callable $callback): void
    {
        $this->closeCallback = $callback;
    }

    public function setSendCallback(callable $callback): void
    {
        $this->sendCallback = $callback;
    }

    public function setCloseConnectionCallback(callable $callback): void
    {
        $this->closeConnectionCallback = $callback;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function getStream(int $streamId): ?H2Stream
    {
        return $this->streams[$streamId] ?? null;
    }

    public function getAllStreams(): array
    {
        return $this->streams;
    }

    public function getLocalSettings(): array
    {
        return $this->localSettings;
    }

    public function getRemoteSettings(): array
    {
        return $this->remoteSettings;
    }

    public function isServer(): bool
    {
        return $this->isServer;
    }

    public function isHandshakeComplete(): bool
    {
        return $this->prefaceReceived && $this->settingsReceived && $this->settingsAckReceived;
    }

    public function close(): void
    {
        if ($this->state === self::STATE_CLOSED) {
            return;
        }

        $this->state = self::STATE_CLOSED;

        // 重置所有扩展
        $this->extensionManager->resetAll();

        // 关闭所有流
        foreach ($this->streams as $stream) {
            $stream->reset();
        }
        $this->streams = [];

        if ($this->closeCallback) {
            call_user_func($this->closeCallback);
        }

        if ($this->closeConnectionCallback) {
            call_user_func($this->closeConnectionCallback);
        }
    }

    public function reset(): void
    {
        $this->state = self::STATE_IDLE;
        $this->buffer = '';
        $this->streams = [];
        $this->streamLastActivity = [];
        $this->lastCleanupTime = 0;
        $this->nextStreamId = 1;
        $this->lastStreamId = 0;
        $this->prefaceReceived = false;
        $this->settingsReceived = false;
        $this->settingsAckReceived = false;
        $this->goawaySent = false;
        $this->goawayReceived = false;

        $this->initializeLocalSettings();
        $this->core->reset();
        $this->extensionManager->resetAll();
    }
}
