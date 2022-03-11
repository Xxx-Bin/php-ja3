<?php

use Workerman\Connection\AsyncTcpConnection;
use \Workerman\Worker;
use \Workerman\WebServer;
use \GatewayWorker\Gateway;
use \GatewayWorker\BusinessWorker;
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/BinaryStream.php';
require_once __DIR__.'/lib/Ja3.php';
require_once __DIR__.'/lib/DataShareServer.php';
$worker = new DataShareServer('127.0.0.1', 2207);
$global = new GlobalData\Client('127.0.0.1:2207');

define('INBOUND','tcp://0.0.0.0:9763');
define('OUTBOUND','tcp://example.com:443');

$web = new Worker(INBOUND);
$web->count = 1;


$web->onConnect = function($connection)
{


    $connection_to_80 = new AsyncTcpConnection(OUTBOUND);
    $connection->pipe($connection_to_80);
    $connection->onMessage     = function ($source, $data) use ($connection_to_80,&$connection) {

        empty($connection->MEXT_REMOTE_PORT) && $connection->MEXT_REMOTE_PORT = $connection_to_80->getLocalPort();
        if(empty($connection->ja3)){
            global $global;
            if($ja3 = Ja3::get($data)){
                $connection->ja3 = $ja3['ja3'];
                $global->__set('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT,$ja3);
            }
        }
        $connection_to_80->send($data);

    };

    $connection_to_80->pipe($connection);
    $connection_to_80->onMessage     = function ($source, $data) use (&$connection,$connection_to_80) {
        if(empty($connection->ja3s)){
            global $global;
            if($ja3 = Ja3::get($data)){
                $_ja3 =  $global->__get('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT);
                $_ja3['ja3s'] = $ja3['ja3s'];
                $connection->ja3s = $ja3['ja3s'];
                $global->__set('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT,$_ja3);
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
