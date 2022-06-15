<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../lib/DataShareClinet.php';
header('Connection: close');
$global = new DataShareClinet('127.0.0.1:2207');
$remote_port_key = 'REMOTE_PORT:'.$_SERVER['REMOTE_PORT'];
$t = microtime(1);
if($ja3 = $global->watch($remote_port_key,1)){
    echo json_encode([
        'ja3_hash' => empty($ja3['ja3']) ? '' : $ja3['ja3'],
        'ja3_str'=>empty($ja3['ja3_str']) ? '' : $ja3['ja3_str'],
        'speed_time' => round(microtime(1) - $t,3),
    ]);
}else{
    echo 'none';
}
