<?php
/**
 * HPACK - HTTP/2 头部压缩编解码器
 *
 * 基于 amphp/hpack 的包装器
 *
 * @link https://tools.ietf.org/html/rfc7541
 */

require_once __DIR__ . '/../vendor/amphp/hpack/src/HPack.php';
require_once __DIR__ . '/../vendor/amphp/hpack/src/HPackException.php';
require_once __DIR__ . '/../vendor/amphp/hpack/src/Internal/HPackNative.php';
require_once __DIR__ . '/../vendor/amphp/hpack/src/Internal/HPackNghttp2.php';

use Amp\Http\HPack as AmpHPack;

/**
 * HPACK 包装器类
 * 提供与原有代码兼容的接口
 */
class HPACK
{
    /** @var AmpHPack */
    private $hpack;

    /** @var int */
    private $maxSize;

    public function __construct(int $maxSize = 4096)
    {
        $this->hpack = new AmpHPack($maxSize);
        $this->maxSize = $maxSize;
    }

    /**
     * 编码头部字段
     *
     * @param array<string, string> $headers 头部数组
     * @return string 编码后的数据
     */
    public function encode(array $headers): string
    {
        // 将关联数组转换为 amphp-hpack 期望的格式 [[name, value], ...]
        $formattedHeaders = [];
        foreach ($headers as $key => $value) {
            if ($value === null) {
                continue;
            }
            if (is_array($value)) {
                continue;
            }
            $formattedHeaders[] = [(string) $key, (string) $value];
        }
        return $this->hpack->encode($formattedHeaders);
    }

    /**
     * 解码头部字段
     *
     * @param string $data HPACK 编码的数据
     * @return array<string, string> 解码后的头部数组
     * @throws \Exception 当解码失败时
     */
    public function decode(string $data): array
    {
        $result = $this->hpack->decode($data, $this->maxSize);

        if ($result === null) {
            throw new \Exception('HPACK 解码失败');
        }

        // 将 amphp-hpack 返回的格式 [[name, value], ...] 转换为关联数组
        $filteredResult = [];
        foreach ($result as $header) {
            if (!is_array($header) || count($header) < 2) {
                continue;
            }
            $name = $header[0];
            $value = $header[1];

            if ($value === null) {
                continue;
            }
            if (is_array($value)) {
                continue;
            }
            $filteredResult[(string) $name] = (string) $value;
        }

        return $filteredResult;
    }

    /**
     * 编码动态表大小更新（RFC 7541 6.3）
     *
     * @param int $newSize 新的动态表大小
     * @return string 编码后的更新指令
     */
    public function encodeDynamicTableSizeUpdate(int $newSize): string
    {
        // amphp/hpack 自动处理动态表大小更新
        $this->maxSize = $newSize;
        $this->hpack = new AmpHPack($newSize);
        return '';
    }

    /**
     * 设置动态表最大大小
     *
     * @param int $size 新的动态表大小
     */
    public function setMaxDynamicTableSize(int $size): void
    {
        $this->maxSize = $size;
        $this->hpack = new AmpHPack($size);
    }
}
