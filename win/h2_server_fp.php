<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../lib/BinaryStream.php';
require_once __DIR__.'/../lib/H2CoreInterface.php';
require_once __DIR__.'/../lib/H2ExtensionInterface.php';
require_once __DIR__.'/../lib/H2ProtocolParser.php';
require_once __DIR__.'/../lib/H2ExtensionManager.php';
require_once __DIR__.'/../lib/H2FingerprintExtension.php';
require_once __DIR__.'/../lib/H2Stream.php';
require_once __DIR__.'/../lib/H2Driver.php';
require_once __DIR__.'/../lib/H2ConnectionManager.php';

use Workerman\Worker;

// 加载配置文件
$configFile = __DIR__ . '/../config.php';
$config = file_exists($configFile) ? require $configFile : [];

// SSL 配置（从配置文件加载，或使用默认值）
$sslConfig = $config['ssl'] ?? [
    'local_cert'  => '',
    'local_pk'    => '',
    'verify_peer' => false,
    'alpn_protocols' => 'h2',
];

// 服务器配置
$serverConfig = $config['server'] ?? [
    'listen' => 'ssl://127.0.0.1:9765',
    'count' => 1,
];

// GlobalData 配置
$globalDataAddress = $config['global_data']['address'] ?? '127.0.0.1:2207';

$global = new GlobalData\Client($globalDataAddress);
define('STREAM_CRYPTO_METHOD_SERVER', STREAM_CRYPTO_METHOD_ANY_SERVER);

// 构建上下文
$context = [
    'socket' => ['tcp_nodelay' => true],
    'ssl' => $sslConfig,
];

require_once __DIR__ . '/../lib/H2Protocol.php';

$h2_server = new Worker($serverConfig['listen'], $context);
$h2_server->count = $serverConfig['count'];
$h2_server->protocol = '\Workerman\Protocols\H2';

$h2_server->onConnect = function($connection) {
    // 创建核心和扩展
    $core = new H2ProtocolParser();
    $extensionManager = new H2ExtensionManager();

    // 注册指纹扩展
    $fingerprintExt = new H2FingerprintExtension([
        //  'extract_window_update_frames' => true, // 每个请求都提取窗口更新帧
        //  'extract_priority_frames' => true, // 每个请求都提取优先级帧
    ]);
    $extensionManager->register($fingerprintExt);
    $extensionManager->enableExtension('h2_fingerprint');

    // 初始化 H2Driver
    $driver = new H2Driver($core, $extensionManager);
    $driver->setServerMode(true);
    H2ConnectionManager::setDriver($connection, $driver);

    // 设置发送回调
    $driver->setSendCallback(function($frameData) use ($connection) {
        $connection->send($frameData);
    });

    // 初始化扩展
    $extensionManager->initializeAll($core);

    // 初始化 H2Driver（在扩展初始化之后，确保扩展回调先执行）
    $driver->initialize();

    // 设置请求回调
    $driver->onRequest(function($streamId, $headers, $data) use ($connection) {
        $driver = H2ConnectionManager::getDriver($connection);
        if (!$driver) return;
        global $global;
        $tls_pf =  $global->__get('REMOTE_PORT:'.$connection->getRemotePort()) ?: [];
        // 获取指纹信息
        $fingerprintExt = $driver->getExtension('h2_fingerprint');
        $h2Fingerprint_str = $fingerprintExt ? $fingerprintExt->getFingerprintString() : '';

        $result = [
            'tls' => $tls_pf,
            'http2' => [
                'fingerprint_str' => $h2Fingerprint_str,
                'fingerprint' => $fingerprintExt ? $fingerprintExt->getFingerprint() : null,
            ],
            'request' => [
                'stream_id' => $streamId,
                'headers' => $headers,
                'address' => $connection->getRemoteAddress(),
            ]
        ];

        $responseBody = json_encode($result, JSON_PRETTY_PRINT);

        // 发送响应
        $driver->sendResponse($streamId, 200, [
            'content-type' => 'application/json',
            'content-length' => strlen($responseBody),
        ], $responseBody);

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
