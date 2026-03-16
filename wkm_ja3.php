<?php

use Workerman\Connection\AsyncTcpConnectionEx;
use \Workerman\Worker;

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/BinaryStream.php';
require_once __DIR__.'/lib/TLS_FP.php';
require_once __DIR__.'/lib/TLS_HELLO_PARSE.php';
require_once __DIR__.'/lib/H2CoreInterface.php';
require_once __DIR__.'/lib/H2ExtensionInterface.php';
require_once __DIR__.'/lib/H2ProtocolParser.php';
require_once __DIR__.'/lib/H2ExtensionManager.php';
require_once __DIR__.'/lib/H2FingerprintExtension.php';
require_once __DIR__.'/lib/H2Stream.php';
require_once __DIR__.'/lib/H2Driver.php';
require_once __DIR__.'/lib/AsyncTcpConnectionEx.php';
require_once __DIR__.'/lib/DataShareServer.php';

// 加载配置文件
$configFile = __DIR__ . '/config.php';
$config = file_exists($configFile) ? require $configFile : [];
$globalDataAddress = $config['global_data']['address'] ?? '127.0.0.1:2207';
$worker = new DataShareServer(explode(':', $globalDataAddress)[0], intval(explode(':', $globalDataAddress)[1]));
// GlobalData 配置
$global = new GlobalData\Client($globalDataAddress);

// 代理配置
$inbound = $config['proxy']['inbound'] ?? 'tcp://0.0.0.0:9763';
$outbound = $config['proxy']['outbound'] ?? 'tcp://127.0.0.100:443';
define('INBOUND', $inbound);
define('OUTBOUND', $outbound);

$web = new Worker(INBOUND);
$web->count = 1;


$web->onConnect = function($connection)
{


    $connection_to_80 = new AsyncTcpConnectionEx(OUTBOUND);
    $connection->pipe($connection_to_80);
    

    // 创建 HTTP/2 核心和指纹扩展
    $connection->h2Core = new H2ProtocolParser();
    $connection->h2FingerprintExt = new H2FingerprintExtension();
    $connection->h2ExtensionManager = new H2ExtensionManager();
    
    // 注册并启用指纹扩展
    $connection->h2ExtensionManager->register($connection->h2FingerprintExt);
    $connection->h2ExtensionManager->enableExtension('h2_fingerprint');
    $connection->h2ExtensionManager->initializeAll($connection->h2Core);

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
        
        if(empty($connection->h2_fp_complete)){
            if($connection->h2Core->parse($data)){
                // 检查指纹是否完整
                if($connection->h2FingerprintExt->isComplete()){
                    $connection->h2_fp_complete = 1;
                    $tls_pf = $global->__get('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT) ?: [];
                    $tls_pf['h2fp'] = $connection->h2FingerprintExt->getFingerprint();      
                    $tls_pf['h2fp_str'] = $connection->h2FingerprintExt->getFingerprintString();
                    $global->__set('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT,$tls_pf);
                }
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



// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
