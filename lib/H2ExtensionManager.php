<?php

require_once __DIR__ . '/H2ExtensionInterface.php';

/**
 * HTTP/2 扩展管理器
 * 
 * 管理所有扩展模块的生命周期和事件分发
 */
class H2ExtensionManager implements H2ExtensionManagerInterface
{
    /**
     * 已注册的扩展
     * @var array<string, H2ExtensionInterface>
     */
    private $extensions = [];

    /**
     * 扩展启用状态
     * @var array<string, bool>
     */
    private $enabled = [];

    /**
     * 核心协议模块
     * @var H2CoreInterface|null
     */
    private $core = null;

    public function register(H2ExtensionInterface $extension): void
    {
        $name = $extension->getName();
        
        if (isset($this->extensions[$name])) {
            throw new \Exception("Extension '{$name}' is already registered");
        }

        $this->extensions[$name] = $extension;
        $this->enabled[$name] = false;

        // 如果核心已初始化，立即初始化扩展
        if ($this->core !== null) {
            $extension->initialize($this->core);
        }
    }

    public function unregister(string $name): void
    {
        if (!isset($this->extensions[$name])) {
            return;
        }

        // 禁用扩展
        if ($this->enabled[$name]) {
            $this->extensions[$name]->disable();
        }

        unset($this->extensions[$name]);
        unset($this->enabled[$name]);
    }

    public function getExtension(string $name): ?H2ExtensionInterface
    {
        return $this->extensions[$name] ?? null;
    }

    public function hasExtension(string $name): bool
    {
        return isset($this->extensions[$name]);
    }

    public function enableExtension(string $name): void
    {
        if (!isset($this->extensions[$name])) {
            throw new \Exception("Extension '{$name}' is not registered");
        }

        if ($this->enabled[$name]) {
            return; // 已经启用
        }

        $extension = $this->extensions[$name];
        
        // 如果核心已初始化，确保扩展也已初始化
        if ($this->core !== null && !$extension->isEnabled()) {
            $extension->initialize($this->core);
        }

        $extension->enable();
        $this->enabled[$name] = true;
    }

    public function disableExtension(string $name): void
    {
        if (!isset($this->extensions[$name])) {
            throw new \Exception("Extension '{$name}' is not registered");
        }

        if (!$this->enabled[$name]) {
            return; // 已经禁用
        }

        $this->extensions[$name]->disable();
        $this->enabled[$name] = false;
    }

    public function getAllExtensions(): array
    {
        return $this->extensions;
    }

    public function getEnabledExtensions(): array
    {
        $enabled = [];
        foreach ($this->extensions as $name => $extension) {
            if ($this->enabled[$name]) {
                $enabled[$name] = $extension;
            }
        }
        return $enabled;
    }

    public function initializeAll(H2CoreInterface $core): void
    {
        $this->core = $core;

        foreach ($this->extensions as $name => $extension) {
            // 只要扩展已启用，就初始化（无论之前是否启用）
            if ($this->enabled[$name]) {
                $extension->initialize($core);
            }
        }
    }

    public function resetAll(): void
    {
        foreach ($this->extensions as $name => $extension) {
            if ($this->enabled[$name]) {
                $extension->reset();
            }
        }
    }

    /**
     * 获取核心协议模块
     *
     * @return H2CoreInterface|null
     */
    public function getCore(): ?H2CoreInterface
    {
        return $this->core;
    }
}
