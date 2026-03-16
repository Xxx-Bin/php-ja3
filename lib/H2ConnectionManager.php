<?php

/**
 * H2 连接数据管理器
 *
 * 用于管理连接的 H2Driver 和其他数据，避免使用动态属性（PHP 8.2+ 废弃）
 */
class H2ConnectionManager
{
    /**
     * 存储连接的 H2Driver
     * @var array<int, H2Driver>
     */
    private static $drivers = [];

    /**
     * 获取连接的 H2Driver
     *
     * @param object $connection 连接对象
     * @return H2Driver|null
     */
    public static function getDriver(object $connection): ?H2Driver
    {
        $connectionId = spl_object_id($connection);
        return self::$drivers[$connectionId] ?? null;
    }

    /**
     * 设置连接的 H2Driver
     *
     * @param object $connection 连接对象
     * @param H2Driver $driver
     * @return void
     */
    public static function setDriver(object $connection, H2Driver $driver): void
    {
        $connectionId = spl_object_id($connection);
        self::$drivers[$connectionId] = $driver;
    }

    /**
     * 移除连接的 H2Driver
     *
     * @param object $connection 连接对象
     * @return void
     */
    public static function removeDriver(object $connection): void
    {
        $connectionId = spl_object_id($connection);
        unset(self::$drivers[$connectionId]);
    }

    /**
     * 检查连接是否有 H2Driver
     *
     * @param object $connection 连接对象
     * @return bool
     */
    public static function hasDriver(object $connection): bool
    {
        $connectionId = spl_object_id($connection);
        return isset(self::$drivers[$connectionId]);
    }
}
