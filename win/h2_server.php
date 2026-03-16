<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../lib/BinaryStream.php';
require_once __DIR__.'/../lib/H2CoreInterface.php';
require_once __DIR__.'/../lib/H2ExtensionInterface.php';
require_once __DIR__.'/../lib/H2ProtocolParser.php';
require_once __DIR__.'/../lib/H2ExtensionManager.php';
require_once __DIR__.'/../lib/H2Stream.php';
require_once __DIR__.'/../lib/H2Driver.php';
require_once __DIR__.'/../lib/H2ConnectionManager.php';

use Workerman\Worker;

// 证书配置
$context = [
    'socket' => ['tcp_nodelay' => true],
    'ssl' => [
        'local_cert'  => '',
        'local_pk'    => '',
        'verify_peer' => false,
        'alpn_protocols' => 'h2',
    ]
];

require_once __DIR__ . '/../lib/H2Protocol.php';

$h2_server = new Worker('ssl://0.0.0.0:9765', $context);
$h2_server->count = 1;
$h2_server->protocol = '\Workerman\Protocols\H2';

$h2_server->onConnect = function($connection) {
    // 创建核心（无扩展）
    $core = new H2ProtocolParser();
    $extensionManager = new H2ExtensionManager();

    // 初始化 H2Driver
    $driver = new H2Driver($core, $extensionManager);
    $driver->setServerMode(true);
    H2ConnectionManager::setDriver($connection, $driver);

    // 设置发送回调
    $driver->setSendCallback(function($frameData) use ($connection) {
        $connection->send($frameData);
    });

    // 初始化 H2Driver（在扩展初始化之后，确保扩展回调先执行）
    $driver->initialize();

    // 设置请求回调
    $driver->onRequest(function($streamId, $headers, $data) use ($connection) {
        $driver = H2ConnectionManager::getDriver($connection);
        if (!$driver) return;

        $responseBody = json_encode([
            'message' => 'Hello HTTP/2',
            'stream_id' => $streamId,
            'headers' => $headers,
        ], JSON_PRETTY_PRINT);

        // 发送响应
        $driver->sendResponse($streamId, 200, [
            'content-type' => 'application/json',
            'content-length' => strlen($responseBody),
        ], $responseBody);
        // 关闭连接
        // $connection->close();
    });

    $connection->onClose = function($connection) {
        $driver = H2ConnectionManager::getDriver($connection);
        if ($driver) {
            $driver->close();
            H2ConnectionManager::removeDriver($connection);
        }
        // 清理协议信息
        \Workerman\Protocols\H2::removeConnectionProtocol($connection);
    };
};

$h2_server->onMessage = function($connection, $request) {
    $driver = H2ConnectionManager::getDriver($connection);
    if (!is_array($request) || !$driver) {
        return;
    }

    if (($request['protocol'] ?? '') !== 'http/2') {
        return;
    }

    if ($request['type'] === 'preface') {
        $driver->getCore()->setPrefaceFound(true);
    }

    $driver->handleInput($request['raw']);
};

if (!defined('GLOBAL_START')) {
    Worker::runAll();
}
