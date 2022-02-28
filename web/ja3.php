<?php
require_once __DIR__ . '/../vendor/autoload.php';

$global = new GlobalData\Client('127.0.0.1:2207');
$remote_port_key = 'REMOTE_PORT:'.$_SERVER['REMOTE_PORT'];
if($global->__isset($remote_port_key)){
    $ja3 = $global->__get($remote_port_key);
    if(!empty($ja3['session_ticket'])){
        $ja3['ja3t_hash'] = $ja3['ja3'];
    }else{
        $ja3['ja3_hash'] = $ja3['ja3'];
    }
    $ja3['ja3s_hash'] = $ja3['ja3s'];
    echo json_encode([
        'ja3t_hash' => empty($ja3['ja3t_hash']) ? '' : $ja3['ja3t_hash'],
        'ja3_hash' => empty($ja3['ja3_hash']) ? '' : $ja3['ja3_hash'],
        'ja3s_hash' => empty($ja3['ja3s_hash']) ? '' : $ja3['ja3s_hash'],
    ]);
}else{
    echo 'none';
}
