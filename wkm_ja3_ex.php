<?php

// 先注册类映射，确保在 autoload 之前
$loader = require_once __DIR__ . '/vendor/autoload.php';
$loader->addClassMap([
    'Workerman\Connection\TcpConnection'=>__DIR__.'/lib/TcpConnection.php',
    'Workerman\Protocols\H2'=>__DIR__.'/lib/H2Protocol.php',
]);

if (! function_exists("array_key_last")) {
    function array_key_last($array) {
        if (!is_array($array) || empty($array)) {
            return NULL;
        }

        return array_keys($array)[count($array)-1];
    }
}
use Workerman\Connection\AsyncTcpConnectionEx;
use \Workerman\Worker;
require_once __DIR__ . '/lib/BinaryStream.php';
require_once __DIR__.'/lib/TLS_FP.php';
require_once __DIR__.'/lib/TLS_HELLO_PARSE.php';
require_once __DIR__.'/lib/H2Driver.php';
require_once __DIR__.'/lib/AsyncTcpConnectionEx.php';
require_once __DIR__.'/lib/DataShareServer.php';

// 加载配置文件
$configFile = __DIR__ . '/config.php';
$config = file_exists($configFile) ? require $configFile : [];

// GlobalData 配置
$globalDataAddress = $config['global_data']['address'] ?? '127.0.0.1:2207';
$worker = new DataShareServer(explode(':', $globalDataAddress)[0], intval(explode(':', $globalDataAddress)[1]));
$global = new GlobalData\Client($globalDataAddress);

// 代理配置
$inbound = $config['proxy']['inbound_ex'] ?? 'tcp://0.0.0.0:9764';
$outbound = $config['proxy']['outbound_ex'] ?? 'tcp://127.0.0.1:9765';
define('INBOUND', $inbound);
define('OUTBOUND', $outbound);

$web = new Worker(INBOUND);
$web->count = 1;


$web->onConnect = function($connection)
{


    $connection_to_80 = new AsyncTcpConnectionEx(OUTBOUND);
    $connection->pipe($connection_to_80);
    
    $connection->onMessage     = function ($source, $data) use ($connection_to_80,&$connection) {
        
        empty($connection->MEXT_REMOTE_PORT) && $connection->MEXT_REMOTE_PORT = $connection_to_80->getLocalPort();
        
        global $global;
        
        if(empty($connection->tls_fp_client)){
            if($tls = TLS_HELLO_PARSE::get($data)){
                $tls_pf['client'] = TLS_FP::init(['layers'=>['ip'=>['ip_ip_proto'=>6],'tls'=>$tls]])->ret();
                $connection->tls_fp_client = 1;
                
                $global->__set('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT,$tls_pf);
            }
        }
        
        $connection_to_80->send($data);

    };

    $connection_to_80->pipe($connection);
    $connection_to_80->onMessage     = function ($source, $data) use (&$connection,$connection_to_80) {
        if(empty($connection->tls_fp_server)){
            global $global;
            if($tls = TLS_HELLO_PARSE::get($data)){
                $tls_pf =  $global->__get('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT) ?: [];
                $tls_pf['sever'] = TLS_FP::init(['layers'=>['ip'=>['ip_ip_proto'=>6],'tls'=>$tls]])->ret_by_server();
                $connection->tls_fp_server = 1;
                
                $global->__set('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT,$tls_pf);
            }
        }
        $connection->send($data);
    };
    $connection_to_80->onClose = function($connection_to_80){
        global $global;
        $global->__unset('REMOTE_PORT:'.$connection_to_80->LocalPort);
    };
    $connection_to_80->onConnect = function($connection_to_80){
        $connection_to_80->LocalPort = $connection_to_80->getLocalPort();
    };
    $connection_to_80->connect();


};


// 引入 H2 协议
require_once __DIR__ . '/win/h2_server_fp.php';




// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
