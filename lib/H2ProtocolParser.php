<?php

require_once __DIR__ . '/H2CoreInterface.php';
require_once __DIR__ . '/BinaryStream.php';
require_once __DIR__ . '/HPACK.php';

/**
 * HTTP/2 协议解析器 - 核心模块
 * 
 * 实现 H2CoreInterface 接口，提供纯净的 HTTP/2 协议解析功能
 * 不包含任何扩展功能（如指纹提取、RTT测量等）
 */
class H2ProtocolParser implements H2CoreInterface
{
    private $buffer = '';
    private $prefaceFound = false;

    private $hpackDecoder = null;
    private $hpackEncoder = null;

    private $frameCallbacks = [];
    private $streamDataCallbacks = [];
    private $streamHeadersCallbacks = [];
    private $settingsCallbacks = [];
    private $priorityCallbacks = [];
    private $windowUpdateCallbacks = [];
    private $pingCallbacks = [];
    private $rstStreamCallbacks = [];
    private $goawayCallbacks = [];

    private $streams = [];

    public function __construct()
    {
        $this->hpackDecoder = new HPACK();
        $this->hpackEncoder = new HPACK();
    }

    public function setPrefaceFound(bool $found): void
    {
        $this->prefaceFound = $found;
    }

    public function isHttp2(): bool
    {
        return $this->prefaceFound;
    }

    public function parse(string $data): bool
    {
        $this->buffer .= $data;

        if (!$this->prefaceFound) {
            $prefacePos = strpos($this->buffer, self::PREFACE);
            if ($prefacePos === false) {
                if (strlen($this->buffer) > strlen(self::PREFACE) + 100) {
                    return false;
                }
                return false;
            }
            $this->prefaceFound = true;
            $this->buffer = substr($this->buffer, $prefacePos + strlen(self::PREFACE));
        }

        $this->parseFrames();
        return true;
    }

    private function parseFrames(): void
    {
        while (strlen($this->buffer) >= 9) {
            $header = substr($this->buffer, 0, 9);
            $parsed = unpack('Clength3/Clength2/Clength1/Ctype/Cflags/Nid', $header);

            $frameLength = ($parsed['length3'] << 16) | ($parsed['length2'] << 8) | $parsed['length1'];
            $frameType = $parsed['type'];
            $frameFlags = $parsed['flags'];
            $streamId = $parsed['id'] & 0x7fffffff;

            if (strlen($this->buffer) < 9 + $frameLength) {
                return;
            }

            $frameData = substr($this->buffer, 9, $frameLength);
            $this->buffer = substr($this->buffer, 9 + $frameLength);

            $this->parseFrame($frameType, $frameFlags, $streamId, $frameData);
        }
    }

    private function parseFrame(int $type, int $flags, int $streamId, string $data): void
    {
        $frameInfo = [
            'type' => $type,
            'flags' => $flags,
            'streamId' => $streamId,
            'data' => $data,
            'length' => strlen($data)
        ];

        $this->triggerFrameCallback($frameInfo);

        switch ($type) {
            case self::FRAME_DATA:
                $this->parseData($data, $flags, $streamId);
                break;
            case self::FRAME_SETTINGS:
                $this->parseSettings($data, $flags);
                break;
            case self::FRAME_PRIORITY:
                $this->parsePriority($data, $streamId);
                break;
            case self::FRAME_WINDOW_UPDATE:
                $this->parseWindowUpdate($data, $streamId);
                break;
            case self::FRAME_HEADERS:
                $this->parseHeaders($data, $flags, $streamId);
                break;
            case self::FRAME_PING:
                $this->parsePing($data, $flags);
                break;
            case self::FRAME_RST_STREAM:
                $this->parseRstStream($data, $streamId);
                break;
            case self::FRAME_GOAWAY:
                $this->parseGoaway($data);
                break;
            case self::FRAME_CONTINUATION:
                $this->parseContinuation($data, $flags, $streamId);
                break;
            case self::FRAME_PUSH_PROMISE:
                $this->parsePushPromise($data, $flags, $streamId);
                break;
        }
    }

    private function parseData(string $data, int $flags, int $streamId): void
    {
        $offset = 0;
        $isPadded = ($flags & self::FLAG_PADDED) !== 0;
        $padding = 0;

        if ($isPadded) {
            $padding = ord($data[0]);
            $offset = 1;
        }

        $endStream = ($flags & self::FLAG_END_STREAM) !== 0;
        $dataLength = strlen($data) - $offset - $padding;

        if ($dataLength < 0) {
            return;
        }

        $payload = substr($data, $offset, $dataLength);

        $this->triggerStreamDataCallback($streamId, $payload, $endStream);

        if (!isset($this->streams[$streamId])) {
            $this->streams[$streamId] = ['data' => '', 'headers' => []];
        }
        $this->streams[$streamId]['data'] .= $payload;
    }

    private function parseSettings(string $data, int $flags): void
    {
        $isAck = ($flags & self::FLAG_ACK) !== 0;

        if ($isAck) {
            $this->triggerSettingsCallback([], true);
            return;
        }

        $settings = [];
        $offset = 0;

        while (strlen($data) >= $offset + 6) {
            $setting = unpack('nkey/Nvalue', substr($data, $offset, 6));
            $settings[$setting['key']] = $setting['value'];

            if ($setting['key'] === self::SETTING_HEADER_TABLE_SIZE) {
                $this->hpackEncoder->setMaxDynamicTableSize($setting['value']);
            }

            $offset += 6;
        }

        if (!empty($settings)) {
            $this->triggerSettingsCallback($settings, false);
        }
    }

    private function parsePriority(string $data, int $streamId): void
    {
        if (strlen($data) < 5) {
            return;
        }

        $parsed = unpack('Nparent/Cweight', $data);
        $parentId = $parsed['parent'] & 0x7fffffff;
        $exclusive = ($parsed['parent'] & 0x80000000) !== 0;
         // $weight + 256 用于区分 priority frame
        $weight = $parsed['weight'] + 1 + 256;

        $this->triggerPriorityCallback($streamId, $parentId, $weight, $exclusive);
    }

    private function parseWindowUpdate(string $data, int $streamId): void
    {
        if (strlen($data) < 4) {
            return;
        }

        $windowSize = unpack('N', $data)[1] & 0x7fffffff;
        $this->triggerWindowUpdateCallback($streamId, $windowSize);
    }

    private function parsePing(string $data, int $flags): void
    {
        if (strlen($data) !== 8) {
            return;
        }

        $isAck = ($flags & self::FLAG_ACK) !== 0;
        $this->triggerPingCallback($data, $isAck);
    }

    private function parseRstStream(string $data, int $streamId): void
    {
        if (strlen($data) < 4) {
            return;
        }

        $errorCode = unpack('N', $data)[1];

        if (isset($this->streams[$streamId])) {
            $this->streams[$streamId]['rstCode'] = $errorCode;
            $this->streams[$streamId]['closed'] = true;
        }

        $this->triggerRstStreamCallback($streamId, $errorCode);
    }

    private function parseGoaway(string $data): void
    {
        if (strlen($data) < 8) {
            return;
        }

        $lastStreamId = unpack('N', $data)[1] & 0x7fffffff;
        $errorCode = unpack('N', substr($data, 4, 4))[1];
        $debugData = strlen($data) > 8 ? substr($data, 8) : '';

        $this->triggerGoawayCallback($lastStreamId, $errorCode, $debugData);
    }

    private function parseContinuation(string $data, int $flags, int $streamId): void
    {
        $endHeaders = ($flags & self::FLAG_END_HEADERS) !== 0;

        try {
            $headers = $this->hpackDecoder->decode($data);

            if (!isset($this->streams[$streamId])) {
                $this->streams[$streamId] = ['data' => '', 'headers' => []];
            }
            $this->streams[$streamId]['headers'] = array_merge($this->streams[$streamId]['headers'], $headers);

            if ($endHeaders) {
                $this->triggerStreamHeadersCallback($streamId, $this->streams[$streamId]['headers'], false);
            }
        } catch (\Exception $e) {
        }
    }

    private function parsePushPromise(string $data, int $flags, int $streamId): void
    {
        $offset = 0;
        $isPadded = ($flags & self::FLAG_PADDED) !== 0;
        $padding = 0;

        if ($isPadded) {
            $padding = ord($data[0]);
            $offset = 1;
        }

        if (strlen($data) < $offset + 4) {
            return;
        }

        $promisedStreamId = unpack('N', substr($data, $offset, 4))[1] & 0x7fffffff;
        $offset += 4;

        $headerBlock = substr($data, $offset, strlen($data) - $offset - $padding);

        try {
            $headers = $this->hpackDecoder->decode($headerBlock);
        } catch (\Exception $e) {
        }
    }

    private function parseHeaders(string $data, int $flags, int $streamId): void
    {
        $offset = 0;
        $padding = 0;
        $isPadded = ($flags & self::FLAG_PADDED) !== 0;
        $isPriority = ($flags & self::FLAG_PRIORITY) !== 0;
        $endStream = ($flags & self::FLAG_END_STREAM) !== 0;
        $endHeaders = ($flags & self::FLAG_END_HEADERS) !== 0;

        if ($isPadded) {
            $padding = ord($data[0]);
            $offset = 1;
        }

        if ($isPriority && strlen($data) >= $offset + 5) {
            $priorityData = substr($data, $offset, 5);
            $offset += 5;
            $parsed = unpack('Nparent/Cweight', $priorityData);
            $parentId = $parsed['parent'] & 0x7fffffff;
            $exclusive = ($parsed['parent'] & 0x80000000) !== 0;
            $weight = $parsed['weight'] + 1 ;
            $this->triggerPriorityCallback($streamId, $parentId, $weight, $exclusive);
        }

        $headerBlockLength = strlen($data) - $offset - $padding;
        if ($headerBlockLength > 0) {
            $headerBlock = substr($data, $offset, $headerBlockLength);

            try {
                $headers = $this->hpackDecoder->decode($headerBlock);

                if (!isset($this->streams[$streamId])) {
                    $this->streams[$streamId] = ['data' => '', 'headers' => []];
                }
                $this->streams[$streamId]['headers'] = $headers;

                if ($endHeaders) {
                    $this->triggerStreamHeadersCallback($streamId, $headers, $endStream);
                }
            } catch (\Exception $e) {
            }
        }
    }

    public function onFrame(callable $callback): void
    {
        $this->frameCallbacks[] = $callback;
    }

    public function onStreamData(callable $callback): void
    {
        $this->streamDataCallbacks[] = $callback;
    }

    public function onStreamHeaders(callable $callback): void
    {
        $this->streamHeadersCallbacks[] = $callback;
    }

    public function onSettings(callable $callback): void
    {
        $this->settingsCallbacks[] = $callback;
    }

    public function onPriority(callable $callback): void
    {
        $this->priorityCallbacks[] = $callback;
    }

    public function onWindowUpdate(callable $callback): void
    {
        $this->windowUpdateCallbacks[] = $callback;
    }

    public function onPing(callable $callback): void
    {
        $this->pingCallbacks[] = $callback;
    }

    public function onRstStream(callable $callback): void
    {
        $this->rstStreamCallbacks[] = $callback;
    }

    public function onGoaway(callable $callback): void
    {
        $this->goawayCallbacks[] = $callback;
    }

    private function triggerFrameCallback(array $frameInfo): void
    {
        foreach ($this->frameCallbacks as $callback) {
            try {
                $callback($frameInfo);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerStreamDataCallback(int $streamId, string $data, bool $endStream): void
    {
        foreach ($this->streamDataCallbacks as $callback) {
            try {
                $callback($streamId, $data, $endStream);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerStreamHeadersCallback(int $streamId, array $headers, bool $endStream): void
    {
        foreach ($this->streamHeadersCallbacks as $callback) {
            try {
                $callback($streamId, $headers, $endStream);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerSettingsCallback(array $settings, bool $isAck): void
    {
        foreach ($this->settingsCallbacks as $callback) {
            try {
                $callback($settings, $isAck);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerPriorityCallback(int $streamId, int $parentId, int $weight, bool $exclusive): void
    {
        foreach ($this->priorityCallbacks as $callback) {
            try {
                $callback($streamId, $parentId, $weight, $exclusive);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerWindowUpdateCallback(int $streamId, int $windowSize): void
    {
        foreach ($this->windowUpdateCallbacks as $callback) {
            try {
                $callback($streamId, $windowSize);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerPingCallback(string $data, bool $isAck): void
    {
        foreach ($this->pingCallbacks as $callback) {
            try {
                $callback($data, $isAck);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerRstStreamCallback(int $streamId, int $errorCode): void
    {
        foreach ($this->rstStreamCallbacks as $callback) {
            try {
                $callback($streamId, $errorCode);
            } catch (\Exception $e) {
            }
        }
    }

    private function triggerGoawayCallback(int $lastStreamId, int $errorCode, string $debugData): void
    {
        foreach ($this->goawayCallbacks as $callback) {
            try {
                $callback($lastStreamId, $errorCode, $debugData);
            } catch (\Exception $e) {
            }
        }
    }

    public function getStreamData(int $streamId): ?string
    {
        return $this->streams[$streamId]['data'] ?? null;
    }

    public function getStreamHeaders(int $streamId): ?array
    {
        return $this->streams[$streamId]['headers'] ?? null;
    }

    public function getAllStreams(): array
    {
        return $this->streams;
    }

    public function getHpackDecoder(): HPACK
    {
        return $this->hpackDecoder;
    }

    public function getHpackEncoder(): HPACK
    {
        return $this->hpackEncoder;
    }

    public function reset(): void
    {
        $this->buffer = '';
        $this->prefaceFound = false;
        $this->streams = [];

        if ($this->hpackDecoder) {
            $this->hpackDecoder->reset();
        }
        if ($this->hpackEncoder) {
            $this->hpackEncoder->reset();
        }
    }

    public function createPingFrame(?string $data = null, bool $ack = false): ?string
    {
        if ($data === null) {
            $data = pack('N', time()) . pack('N', mt_rand());
        }

        return $this->buildFrame(self::FRAME_PING, $ack ? self::FLAG_ACK : 0, 0, $data);
    }

    public function createDataFrame(int $streamId, string $data, bool $endStream = false): string
    {
        $flags = $endStream ? self::FLAG_END_STREAM : 0;
        return $this->buildFrame(self::FRAME_DATA, $flags, $streamId, $data);
    }

    public function createHeadersFrame(int $streamId, array $headers, bool $endStream = false, bool $endHeaders = true): string
    {
        $headerBlock = $this->hpackEncoder->encode($headers);
        $flags = 0;
        if ($endStream) {
            $flags |= self::FLAG_END_STREAM;
        }
        if ($endHeaders) {
            $flags |= self::FLAG_END_HEADERS;
        }
        return $this->buildFrame(self::FRAME_HEADERS, $flags, $streamId, $headerBlock);
    }

    public function createSettingsFrame(array $settings, bool $ack = false): string
    {
        if ($ack) {
            return $this->buildFrame(self::FRAME_SETTINGS, self::FLAG_ACK, 0, '');
        }

        $payload = '';
        foreach ($settings as $key => $value) {
            $payload .= pack('n', $key) . pack('N', $value);
        }
        return $this->buildFrame(self::FRAME_SETTINGS, 0, 0, $payload);
    }

    public function createWindowUpdateFrame(int $streamId, int $increment): string
    {
        $payload = pack('N', $increment & 0x7fffffff);
        return $this->buildFrame(self::FRAME_WINDOW_UPDATE, 0, $streamId, $payload);
    }

    public function createRstStreamFrame(int $streamId, int $errorCode): string
    {
        $payload = pack('N', $errorCode);
        return $this->buildFrame(self::FRAME_RST_STREAM, 0, $streamId, $payload);
    }

    public function createGoawayFrame(int $lastStreamId, int $errorCode, string $debugData = ''): string
    {
        $payload = pack('N', $lastStreamId & 0x7fffffff) . pack('N', $errorCode) . $debugData;
        return $this->buildFrame(self::FRAME_GOAWAY, 0, 0, $payload);
    }

    public function createPriorityFrame(int $streamId, int $parentId, int $weight, bool $exclusive = false): string
    {
        $parentId = $parentId & 0x7fffffff;
        if ($exclusive) {
            $parentId |= 0x80000000;
        }
        $payload = pack('N', $parentId) . chr($weight - 1);
        return $this->buildFrame(self::FRAME_PRIORITY, 0, $streamId, $payload);
    }

    public function createContinuationFrame(int $streamId, array $headers, bool $endHeaders = true): string
    {
        $headerBlock = $this->hpackEncoder->encode($headers);
        $flags = $endHeaders ? self::FLAG_END_HEADERS : 0;
        return $this->buildFrame(self::FRAME_CONTINUATION, $flags, $streamId, $headerBlock);
    }

    private function buildFrame(int $type, int $flags, int $streamId, string $payload): string
    {
        $length = strlen($payload);

        if ($length > 0xFFFFFF) {
            throw new \Exception('Frame payload too large');
        }

        $frame = chr(($length >> 16) & 0xFF);
        $frame .= chr(($length >> 8) & 0xFF);
        $frame .= chr($length & 0xFF);
        $frame .= chr($type);
        $frame .= chr($flags);
        $frame .= pack('N', $streamId & 0x7fffffff);
        $frame .= $payload;

        return $frame;
    }

    public static function getFrameTypeName(int $type): string
    {
        $names = [
            self::FRAME_DATA => 'DATA',
            self::FRAME_HEADERS => 'HEADERS',
            self::FRAME_PRIORITY => 'PRIORITY',
            self::FRAME_RST_STREAM => 'RST_STREAM',
            self::FRAME_SETTINGS => 'SETTINGS',
            self::FRAME_PUSH_PROMISE => 'PUSH_PROMISE',
            self::FRAME_PING => 'PING',
            self::FRAME_GOAWAY => 'GOAWAY',
            self::FRAME_WINDOW_UPDATE => 'WINDOW_UPDATE',
            self::FRAME_CONTINUATION => 'CONTINUATION',
        ];
        return $names[$type] ?? 'UNKNOWN';
    }

    public static function getErrorName(int $errorCode): string
    {
        $names = [
            self::ERROR_NO_ERROR => 'NO_ERROR',
            self::ERROR_PROTOCOL_ERROR => 'PROTOCOL_ERROR',
            self::ERROR_INTERNAL_ERROR => 'INTERNAL_ERROR',
            self::ERROR_FLOW_CONTROL_ERROR => 'FLOW_CONTROL_ERROR',
            self::ERROR_SETTINGS_TIMEOUT => 'SETTINGS_TIMEOUT',
            self::ERROR_STREAM_CLOSED => 'STREAM_CLOSED',
            self::ERROR_FRAME_SIZE_ERROR => 'FRAME_SIZE_ERROR',
            self::ERROR_REFUSED_STREAM => 'REFUSED_STREAM',
            self::ERROR_CANCEL => 'CANCEL',
            self::ERROR_COMPRESSION_ERROR => 'COMPRESSION_ERROR',
            self::ERROR_CONNECT_ERROR => 'CONNECT_ERROR',
            self::ERROR_ENHANCE_YOUR_CALM => 'ENHANCE_YOUR_CALM',
            self::ERROR_INADEQUATE_SECURITY => 'INADEQUATE_SECURITY',
            self::ERROR_HTTP_1_1_REQUIRED => 'HTTP_1_1_REQUIRED',
        ];
        return $names[$errorCode] ?? 'UNKNOWN_ERROR';
    }

    public static function getSettingName(int $settingId): string
    {
        $names = [
            self::SETTING_HEADER_TABLE_SIZE => 'HEADER_TABLE_SIZE',
            self::SETTING_ENABLE_PUSH => 'ENABLE_PUSH',
            self::SETTING_MAX_CONCURRENT_STREAMS => 'MAX_CONCURRENT_STREAMS',
            self::SETTING_INITIAL_WINDOW_SIZE => 'INITIAL_WINDOW_SIZE',
            self::SETTING_MAX_FRAME_SIZE => 'MAX_FRAME_SIZE',
            self::SETTING_MAX_HEADER_LIST_SIZE => 'MAX_HEADER_LIST_SIZE',
        ];
        return $names[$settingId] ?? 'UNKNOWN_SETTING';
    }
}
