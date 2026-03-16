<?php

require_once __DIR__ . '/H2ExtensionInterface.php';

/**
 * HTTP/2 指纹提取扩展
 *
 * 实现 H2ExtensionInterface 接口，提供 HTTP/2 指纹提取功能
 */
class H2FingerprintExtension implements H2ExtensionInterface
{
    const NAME = 'h2_fingerprint';
    const VERSION = '1.0.0';

    private $h2fp = [];
    private $settingsComplete = false;
    private $headersComplete = false;
    private $fingerprintComplete = false;
    private $settings = [];
    private $windowUpdateSize = null;
    private $priorities = [];
    private $headerPriorities = [];
    private $pseudoHeaders = [];
    private $enabled = false;
    private $initialized = false;
    private $core = null;
    private $config = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'extract_settings' => true,
            'extract_window_update' => true,
            'extract_priority' => true,
            'extract_window_update_frames' => false,
            'extract_priority_frames' => false,
            'extract_pseudo_headers' => true,
        ], $config);
        $this->reset();
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function getVersion(): string
    {
        return self::VERSION;
    }

    public function initialize(H2CoreInterface $core): void
    {
        if ($this->initialized) {
            return;
        }

        $this->core = $core;

        // 注册回调
        if ($this->config['extract_settings']) {
            $core->onSettings([$this, 'onSettings']);
        }

        if ($this->config['extract_window_update']) {
            $core->onWindowUpdate([$this, 'onWindowUpdate']);
        }

        if ($this->config['extract_priority']) {
            $core->onPriority([$this, 'onPriority']);
        }

        if ($this->config['extract_pseudo_headers']) {
            $core->onStreamHeaders([$this, 'onStreamHeaders']);
        }

        $this->initialized = true;
    }

    public function enable(): void
    {
        $this->enabled = true;
    }

    public function disable(): void
    {
        $this->enabled = false;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function reset(): void
    {
        $this->h2fp = [];
        $this->settingsComplete = false;
        $this->headersComplete = false;
        $this->fingerprintComplete = false;
        $this->settings = [];
        $this->windowUpdateSize = null;
        $this->priorities = [];
        $this->headerPriorities = [];
        $this->pseudoHeaders = [];
    }

    public function getConfig(): array
    {
        return $this->config;
    }

    public function setConfig(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }

    public function onSettings(array $settings, bool $isAck): void
    {
        if (!$this->enabled || $isAck) {
            return;
        }

        if (!empty($settings)) {
            $this->settings = $settings;
            $settingsParts = [];
            foreach ($settings as $key => $value) {
                $settingsParts[] = $key . ':' . $value;
            }
            $this->h2fp['S[;]'] = implode(';', $settingsParts);
            $this->settingsComplete = true;
            $this->checkComplete();
        }
    }

    public function onWindowUpdate(int $streamId, int $windowSize): void
    {
        if (!$this->enabled) {
            return;
        }

        if (!isset($this->h2fp['WU'])) {
            $this->h2fp['WU'] = $windowSize;
           
        }
        if($this->config['extract_window_update_frames']){
            if(!isset($this->h2fp['WUF[,]'])){
                $this->h2fp['WUF[,]'] = [];
            }
            $this->h2fp['WUF[,]'][] = $windowSize;
        }
        
    }

    public function onPriority(int $streamId, int $parentId, int $weight, bool $exclusive): void
    {
    
        if (!$this->enabled) {
            return;
        }

        $priorityInfo = implode(':', [$streamId, $exclusive ? 1 : 0, $parentId, $weight]);
        $this->priorities[] = $priorityInfo;

        if (!isset($this->h2fp['P[,]']) && $weight > 256) {
            $weight -= 256;
            $this->h2fp['P[,]'] = [$streamId, $exclusive ? 1 : 0, $parentId, $weight];
        }
        if ($this->config['extract_priority_frames']) {
            if (!isset($this->h2fp['PF[,]'])) {
                $this->h2fp['PF[,]'] = [];
            }
            $this->h2fp['PF[,]'][] = $priorityInfo;
        }
    }

    public function onStreamHeaders(int $streamId, array $headers, bool $endStream): void
    {
        if (!$this->enabled) {
            return;
        }

        $pseudoHeaders = [];
        foreach ($headers as $name => $value) {
            if (strpos($name, ':') === 0) {
                $pseudoHeaders[] = substr($name, 1, 1);
            }
        }

        if (!empty($pseudoHeaders)) {
            $this->pseudoHeaders = array_merge($this->pseudoHeaders, $pseudoHeaders);
            $this->h2fp['PS[,]'] = implode(',', $pseudoHeaders);
            $this->headersComplete = true;
            $this->checkComplete();
        }
    }

    private function checkComplete(): void
    {
        if ($this->settingsComplete && $this->headersComplete) {
            $this->fingerprintComplete = true;
        }
    }

    public function getFingerprint(): array
    {
        return $this->h2fp;
    }

    public function getFingerprintString(): string
    {
        if (empty($this->h2fp)) {
            return '';
        }

        $parts = [
            $this->h2fp['S[;]'] ?? '',
            $this->h2fp['WU'] ?? '00',
            empty($this->h2fp['P[,]']) ? '0' : implode(',', $this->h2fp['P[,]']),
            $this->h2fp['PS[,]'] ?? ''
        ];

        return implode('|', $parts);
    }

    public function isComplete(): bool
    {
        return $this->fingerprintComplete;
    }

    public function isSettingsComplete(): bool
    {
        return $this->settingsComplete;
    }

    public function isHeadersComplete(): bool
    {
        return $this->headersComplete;
    }

    public function getSettings(): array
    {
        return $this->settings;
    }

    public function getWindowUpdateSize(): ?int
    {
        return $this->windowUpdateSize;
    }

    public function getPriorities(): array
    {
        return $this->priorities;
    }

    public function getHeaderPriorities(): array
    {
        return $this->headerPriorities;
    }

    public function getPseudoHeaders(): array
    {
        return $this->pseudoHeaders;
    }
}
