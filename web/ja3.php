<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../lib/DataShareClinet.php';
// 加载配置文件
$configFile = __DIR__ . '/../config.php';
$config = file_exists($configFile) ? require $configFile : [];
header('Connection: close');
$globalDataAddress = $config['global_data']['address'] ?? '127.0.0.1:2207';
$global = new DataShareClinet($globalDataAddress);
$remote_port_key = 'REMOTE_PORT:'.$_SERVER['REMOTE_PORT'];
$t = microtime(1);
if($tls_fp = $global->watch($remote_port_key,1)){
    $tls_fp['speed_time'] = round(microtime(1) - $t,3);
    echo json_encode($tls_fp);
}else{
    echo 'none';
}
