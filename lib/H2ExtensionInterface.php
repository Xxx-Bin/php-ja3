<?php

/**
 * HTTP/2 扩展模块接口
 * 
 * 定义 H2 协议扩展功能的标准接口
 * 所有扩展模块（如指纹提取、RTT测量等）必须实现此接口
 */
interface H2ExtensionInterface
{
    /**
     * 获取扩展名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 获取扩展版本
     *
     * @return string
     */
    public function getVersion(): string;

    /**
     * 初始化扩展
     *
     * @param H2CoreInterface $core 核心协议模块
     * @return void
     */
    public function initialize(H2CoreInterface $core): void;

    /**
     * 启用扩展
     *
     * @return void
     */
    public function enable(): void;

    /**
     * 禁用扩展
     *
     * @return void
     */
    public function disable(): void;

    /**
     * 检查扩展是否已启用
     *
     * @return bool
     */
    public function isEnabled(): bool;

    /**
     * 重置扩展状态
     *
     * @return void
     */
    public function reset(): void;

    /**
     * 获取扩展配置
     *
     * @return array
     */
    public function getConfig(): array;

    /**
     * 设置扩展配置
     *
     * @param array $config
     * @return void
     */
    public function setConfig(array $config): void;
}

/**
 * HTTP/2 扩展管理器接口
 * 
 * 管理所有扩展模块的生命周期和事件分发
 */
interface H2ExtensionManagerInterface
{
    /**
     * 注册扩展
     *
     * @param H2ExtensionInterface $extension
     * @return void
     */
    public function register(H2ExtensionInterface $extension): void;

    /**
     * 注销扩展
     *
     * @param string $name 扩展名称
     * @return void
     */
    public function unregister(string $name): void;

    /**
     * 获取扩展
     *
     * @param string $name
     * @return H2ExtensionInterface|null
     */
    public function getExtension(string $name): ?H2ExtensionInterface;

    /**
     * 检查扩展是否已注册
     *
     * @param string $name
     * @return bool
     */
    public function hasExtension(string $name): bool;

    /**
     * 启用扩展
     *
     * @param string $name
     * @return void
     */
    public function enableExtension(string $name): void;

    /**
     * 禁用扩展
     *
     * @param string $name
     * @return void
     */
    public function disableExtension(string $name): void;

    /**
     * 获取所有已注册的扩展
     *
     * @return array<string, H2ExtensionInterface>
     */
    public function getAllExtensions(): array;

    /**
     * 获取所有已启用的扩展
     *
     * @return array<string, H2ExtensionInterface>
     */
    public function getEnabledExtensions(): array;

    /**
     * 初始化所有扩展
     *
     * @param H2CoreInterface $core
     * @return void
     */
    public function initializeAll(H2CoreInterface $core): void;

    /**
     * 重置所有扩展
     *
     * @return void
     */
    public function resetAll(): void;
}
