<?php

/**
 * HTTP/2 流管理类
 * 实现 HTTP/2 协议中的流状态管理和流量控制
 */
class H2Stream
{
    /**
     * 流状态常量
     */
    const STATE_IDLE = 'idle';
    const STATE_RESERVED_LOCAL = 'reserved_local';
    const STATE_RESERVED_REMOTE = 'reserved_remote';
    const STATE_OPEN = 'open';
    const STATE_HALF_CLOSED_LOCAL = 'half_closed_local';
    const STATE_HALF_CLOSED_REMOTE = 'half_closed_remote';
    const STATE_CLOSED = 'closed';

    /**
     * 流 ID
     * @var int
     */
    private $streamId;

    /**
     * 当前流状态
     * @var string
     */
    private $state;

    /**
     * 本地窗口大小（发送窗口）
     * @var int
     */
    private $windowSize;

    /**
     * 远程窗口大小（接收窗口）
     * @var int
     */
    private $remoteWindowSize;

    /**
     * 流优先级信息
     * @var array
     */
    private $priority;

    /**
     * 请求/响应头信息
     * @var array
     */
    private $headers;

    /**
     * 接收到的数据缓冲区
     * @var string
     */
    private $data;

    /**
     * 默认窗口大小 (64KB)
     */
    const DEFAULT_WINDOW_SIZE = 65535;

    /**
     * 最大窗口大小 (2^31 - 1)
     */
    const MAX_WINDOW_SIZE = 2147483647;

    /**
     * 构造函数
     *
     * @param int $streamId 流 ID
     * @param string $initialState 初始状态，默认为 IDLE
     * @param int $initialWindowSize 初始窗口大小
     */
    public function __construct(int $streamId, string $initialState = self::STATE_IDLE, int $initialWindowSize = self::DEFAULT_WINDOW_SIZE)
    {
        $this->streamId = $streamId;
        $this->state = $initialState;
        $this->windowSize = $initialWindowSize;
        $this->remoteWindowSize = $initialWindowSize;
        $this->priority = [
            'parentId' => 0,
            'weight' => 16,
            'exclusive' => false
        ];
        $this->headers = [];
        $this->data = '';
    }

    /**
     * 获取流 ID
     *
     * @return int
     */
    public function getStreamId(): int
    {
        return $this->streamId;
    }

    /**
     * 获取当前流状态
     *
     * @return string
     */
    public function getState(): string
    {
        return $this->state;
    }

    /**
     * 检查流是否处于指定状态
     *
     * @param string $state
     * @return bool
     */
    public function isState(string $state): bool
    {
        return $this->state === $state;
    }

    /**
     * 检查流是否已关闭
     *
     * @return bool
     */
    public function isClosed(): bool
    {
        return $this->state === self::STATE_CLOSED;
    }

    /**
     * 打开流（从 IDLE 转换到 OPEN）
     * 用于客户端发送 HEADERS 帧或服务器接收 HEADERS 帧
     *
     * @return bool
     * @throws \Exception
     */
    public function open(): bool
    {
        if ($this->state !== self::STATE_IDLE) {
            throw new \Exception("Cannot open stream from state: {$this->state}");
        }

        $this->state = self::STATE_OPEN;
        return true;
    }

    /**
     * 发送 HEADERS 帧（客户端）
     * IDLE -> OPEN (客户端发起请求)
     * RESERVED_LOCAL -> HALF_CLOSED_REMOTE (服务器推送响应)
     *
     * @param array $headers 要发送的头信息
     * @param bool $endStream 是否结束流
     * @return bool
     * @throws \Exception
     */
    public function sendHeaders(array $headers, bool $endStream = false): bool
    {
        switch ($this->state) {
            case self::STATE_IDLE:
                $this->state = $endStream ? self::STATE_HALF_CLOSED_LOCAL : self::STATE_OPEN;
                break;
            case self::STATE_RESERVED_LOCAL:
                $this->state = $endStream ? self::STATE_CLOSED : self::STATE_HALF_CLOSED_REMOTE;
                break;
            case self::STATE_OPEN:
                if ($endStream) {
                    $this->state = self::STATE_HALF_CLOSED_LOCAL;
                }
                break;
            case self::STATE_HALF_CLOSED_REMOTE:
                if ($endStream) {
                    $this->state = self::STATE_CLOSED;
                }
                break;
            default:
                throw new \Exception("Cannot send headers in state: {$this->state}");
        }

        $this->headers = array_merge($this->headers, $headers);
        return true;
    }

    /**
     * 发送 DATA 帧（客户端）
     * 检查窗口大小并更新状态
     *
     * @param string $data 要发送的数据
     * @param bool $endStream 是否结束流
     * @return bool
     * @throws \Exception
     */
    public function sendData(string $data, bool $endStream = false): bool
    {
        $dataLength = strlen($data);

        if ($dataLength > 0 && !$this->canSend($dataLength)) {
            throw new \Exception("Flow control: window size exceeded");
        }

        switch ($this->state) {
            case self::STATE_OPEN:
                if ($endStream) {
                    $this->state = self::STATE_HALF_CLOSED_LOCAL;
                }
                break;
            case self::STATE_HALF_CLOSED_REMOTE:
                if ($endStream) {
                    $this->state = self::STATE_CLOSED;
                }
                break;
            default:
                throw new \Exception("Cannot send data in state: {$this->state}");
        }

        $this->windowSize -= $dataLength;
        return true;
    }

    /**
     * 接收 HEADERS 帧（服务器）
     * IDLE -> OPEN (服务器接收请求)
     * RESERVED_REMOTE -> HALF_CLOSED_LOCAL (客户端推送响应)
     *
     * @param array $headers 接收到的头信息
     * @param bool $endStream 是否结束流
     * @return bool
     * @throws \Exception
     */
    public function receiveHeaders(array $headers, bool $endStream = false): bool
    {
        switch ($this->state) {
            case self::STATE_IDLE:
                $this->state = $endStream ? self::STATE_HALF_CLOSED_REMOTE : self::STATE_OPEN;
                break;
            case self::STATE_RESERVED_REMOTE:
                $this->state = $endStream ? self::STATE_CLOSED : self::STATE_HALF_CLOSED_LOCAL;
                break;
            case self::STATE_OPEN:
                if ($endStream) {
                    $this->state = self::STATE_HALF_CLOSED_REMOTE;
                }
                break;
            case self::STATE_HALF_CLOSED_LOCAL:
                if ($endStream) {
                    $this->state = self::STATE_CLOSED;
                }
                break;
            default:
                throw new \Exception("Cannot receive headers in state: {$this->state}");
        }

        $this->headers = array_merge($this->headers, $headers);
        return true;
    }

    /**
     * 接收 DATA 帧（服务器）
     * 检查窗口大小并存储数据
     *
     * @param string $data 接收到的数据
     * @param bool $endStream 是否结束流
     * @return bool
     * @throws \Exception
     */
    public function receiveData(string $data, bool $endStream = false): bool
    {
        $dataLength = strlen($data);

        if ($dataLength > 0 && !$this->canReceive($dataLength)) {
            throw new \Exception("Flow control: remote window size exceeded");
        }

        switch ($this->state) {
            case self::STATE_OPEN:
                if ($endStream) {
                    $this->state = self::STATE_HALF_CLOSED_REMOTE;
                }
                break;
            case self::STATE_HALF_CLOSED_LOCAL:
                if ($endStream) {
                    $this->state = self::STATE_CLOSED;
                }
                break;
            default:
                throw new \Exception("Cannot receive data in state: {$this->state}");
        }

        $this->remoteWindowSize -= $dataLength;
        $this->data .= $data;
        return true;
    }

    /**
     * 关闭本地端（发送 RST_STREAM 或发送 END_STREAM 后）
     * OPEN -> HALF_CLOSED_LOCAL
     * HALF_CLOSED_REMOTE -> CLOSED
     *
     * @return bool
     * @throws \Exception
     */
    public function closeLocal(): bool
    {
        switch ($this->state) {
            case self::STATE_OPEN:
                $this->state = self::STATE_HALF_CLOSED_LOCAL;
                break;
            case self::STATE_HALF_CLOSED_REMOTE:
                $this->state = self::STATE_CLOSED;
                break;
            case self::STATE_HALF_CLOSED_LOCAL:
            case self::STATE_CLOSED:
                break;
            default:
                throw new \Exception("Cannot close local in state: {$this->state}");
        }

        return true;
    }

    /**
     * 关闭远程端（接收 RST_STREAM 或接收 END_STREAM 后）
     * OPEN -> HALF_CLOSED_REMOTE
     * HALF_CLOSED_LOCAL -> CLOSED
     *
     * @return bool
     * @throws \Exception
     */
    public function closeRemote(): bool
    {
        switch ($this->state) {
            case self::STATE_OPEN:
                $this->state = self::STATE_HALF_CLOSED_REMOTE;
                break;
            case self::STATE_HALF_CLOSED_LOCAL:
                $this->state = self::STATE_CLOSED;
                break;
            case self::STATE_HALF_CLOSED_REMOTE:
            case self::STATE_CLOSED:
                break;
            default:
                throw new \Exception("Cannot close remote in state: {$this->state}");
        }

        return true;
    }

    /**
     * 重置流（接收或发送 RST_STREAM 帧）
     * 任何状态 -> CLOSED
     *
     * @param int $errorCode 错误代码
     * @return bool
     */
    public function reset(int $errorCode = 0): bool
    {
        $this->state = self::STATE_CLOSED;
        $this->data = '';
        return true;
    }

    /**
     * 保留本地流（服务器发起 PUSH_PROMISE）
     * IDLE -> RESERVED_LOCAL
     *
     * @return bool
     * @throws \Exception
     */
    public function reserveLocal(): bool
    {
        if ($this->state !== self::STATE_IDLE) {
            throw new \Exception("Cannot reserve local stream from state: {$this->state}");
        }

        $this->state = self::STATE_RESERVED_LOCAL;
        return true;
    }

    /**
     * 保留远程流（客户端接收 PUSH_PROMISE）
     * IDLE -> RESERVED_REMOTE
     *
     * @return bool
     * @throws \Exception
     */
    public function reserveRemote(): bool
    {
        if ($this->state !== self::STATE_IDLE) {
            throw new \Exception("Cannot reserve remote stream from state: {$this->state}");
        }

        $this->state = self::STATE_RESERVED_REMOTE;
        return true;
    }

    /**
     * 设置流优先级
     *
     * @param int $parentId 父流 ID
     * @param int $weight 权重 (1-256)
     * @param bool $exclusive 是否独占
     * @return bool
     * @throws \Exception
     */
    public function setPriority(int $parentId, int $weight, bool $exclusive = false): bool
    {
        if ($weight < 1 || $weight > 256) {
            throw new \Exception("Priority weight must be between 1 and 256");
        }

        $this->priority = [
            'parentId' => $parentId,
            'weight' => $weight,
            'exclusive' => $exclusive
        ];

        return true;
    }

    /**
     * 获取流优先级
     *
     * @return array
     */
    public function getPriority(): array
    {
        return $this->priority;
    }

    /**
     * 获取父流 ID
     *
     * @return int
     */
    public function getParentId(): int
    {
        return $this->priority['parentId'];
    }

    /**
     * 获取权重
     *
     * @return int
     */
    public function getWeight(): int
    {
        return $this->priority['weight'];
    }

    /**
     * 检查是否为独占流
     *
     * @return bool
     */
    public function isExclusive(): bool
    {
        return $this->priority['exclusive'];
    }

    /**
     * 更新本地窗口大小（发送 WINDOW_UPDATE 后）
     *
     * @param int $increment 增量（必须为正数）
     * @return bool
     * @throws \Exception
     */
    public function updateWindowSize(int $increment): bool
    {
        if ($increment <= 0) {
            throw new \Exception("Window size increment must be positive");
        }

        $newSize = $this->windowSize + $increment;
        if ($newSize > self::MAX_WINDOW_SIZE) {
            throw new \Exception("Window size overflow");
        }

        $this->windowSize = $newSize;
        return true;
    }

    /**
     * 更新远程窗口大小（接收 WINDOW_UPDATE 后）
     *
     * @param int $increment 增量（必须为正数）
     * @return bool
     * @throws \Exception
     */
    public function updateRemoteWindowSize(int $increment): bool
    {
        if ($increment <= 0) {
            throw new \Exception("Remote window size increment must be positive");
        }

        $newSize = $this->remoteWindowSize + $increment;
        if ($newSize > self::MAX_WINDOW_SIZE) {
            throw new \Exception("Remote window size overflow");
        }

        $this->remoteWindowSize = $newSize;
        return true;
    }

    /**
     * 设置本地窗口大小（SETTINGS 帧更新初始窗口大小）
     *
     * @param int $newSize 新的窗口大小
     * @return bool
     * @throws \Exception
     */
    public function setWindowSize(int $newSize): bool
    {
        if ($newSize < 0 || $newSize > self::MAX_WINDOW_SIZE) {
            throw new \Exception("Invalid window size");
        }

        $this->windowSize = $newSize;
        return true;
    }

    /**
     * 设置远程窗口大小（SETTINGS 帧更新初始窗口大小）
     *
     * @param int $newSize 新的窗口大小
     * @return bool
     * @throws \Exception
     */
    public function setRemoteWindowSize(int $newSize): bool
    {
        if ($newSize < 0 || $newSize > self::MAX_WINDOW_SIZE) {
            throw new \Exception("Invalid remote window size");
        }

        $this->remoteWindowSize = $newSize;
        return true;
    }

    /**
     * 获取本地窗口大小
     *
     * @return int
     */
    public function getWindowSize(): int
    {
        return $this->windowSize;
    }

    /**
     * 获取远程窗口大小
     *
     * @return int
     */
    public function getRemoteWindowSize(): int
    {
        return $this->remoteWindowSize;
    }

    /**
     * 检查是否可以发送指定大小的数据
     *
     * @param int $dataLength 数据长度
     * @return bool
     */
    public function canSend(int $dataLength): bool
    {
        return $dataLength <= $this->windowSize;
    }

    /**
     * 检查是否可以接收指定大小的数据
     *
     * @param int $dataLength 数据长度
     * @return bool
     */
    public function canReceive(int $dataLength): bool
    {
        return $dataLength <= $this->remoteWindowSize;
    }

    /**
     * 获取可发送的数据大小
     *
     * @return int
     */
    public function getSendableSize(): int
    {
        return max(0, $this->windowSize);
    }

    /**
     * 获取可接收的数据大小
     *
     * @return int
     */
    public function getReceivableSize(): int
    {
        return max(0, $this->remoteWindowSize);
    }

    /**
     * 设置头信息
     *
     * @param array $headers
     * @return void
     */
    public function setHeaders(array $headers): void
    {
        $this->headers = $headers;
    }

    /**
     * 获取头信息
     *
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * 追加数据到缓冲区
     *
     * @param string $data
     * @return void
     */
    public function appendData(string $data): void
    {
        $this->data .= $data;
    }

    /**
     * 获取数据
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * 清空数据缓冲区
     *
     * @return void
     */
    public function clearData(): void
    {
        $this->data = '';
    }

    /**
     * 获取流信息摘要
     *
     * @return array
     */
    public function getInfo(): array
    {
        return [
            'streamId' => $this->streamId,
            'state' => $this->state,
            'windowSize' => $this->windowSize,
            'remoteWindowSize' => $this->remoteWindowSize,
            'priority' => $this->priority,
            'dataLength' => strlen($this->data),
            'headersCount' => count($this->headers)
        ];
    }

    /**
     * 获取有效的流状态列表
     *
     * @return array
     */
    public static function getValidStates(): array
    {
        return [
            self::STATE_IDLE,
            self::STATE_RESERVED_LOCAL,
            self::STATE_RESERVED_REMOTE,
            self::STATE_OPEN,
            self::STATE_HALF_CLOSED_LOCAL,
            self::STATE_HALF_CLOSED_REMOTE,
            self::STATE_CLOSED
        ];
    }

    /**
     * 检查指定状态是否有效
     *
     * @param string $state
     * @return bool
     */
    public static function isValidState(string $state): bool
    {
        return in_array($state, self::getValidStates(), true);
    }
}
