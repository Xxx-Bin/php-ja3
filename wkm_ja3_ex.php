<?php

use Workerman\Connection\AsyncTcpConnection;
use \Workerman\Worker;
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/lib/BinaryStream.php';
require_once __DIR__.'/lib/TLS_FP.php';
require_once __DIR__.'/lib/TLS_HELLO_PARSE.php';
require_once __DIR__.'/lib/DataShareServer.php';
$worker = new DataShareServer('127.0.0.1', 2207);
$global = new GlobalData\Client('127.0.0.1:2207');

define('INBOUND','tcp://0.0.0.0:9764');
define('OUTBOUND','tcp://127.0.0.1:9765');

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
        if(empty($connection->ja3s)){
            global $global;
            if($tls = TLS_HELLO_PARSE::get($data)){
                $tls_pf =  $global->__get('REMOTE_PORT:'.$connection->MEXT_REMOTE_PORT);
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

//Need to add the following to ./vendor/workerman/workerman/Connection/TcpConnection.php line 745
/*

		if(defined('STREAM_CRYPTO_METHOD_SERVER')){
                 $type = \STREAM_CRYPTO_METHOD_SERVER;
        }else{
                $type = \STREAM_CRYPTO_METHOD_SSLv2_SERVER | \STREAM_CRYPTO_METHOD_SSLv23_SERVER;
        }
 */
define('STREAM_CRYPTO_METHOD_SERVER',STREAM_CRYPTO_METHOD_ANY_SERVER );
// 证书最好是申请的证书
$context = array(
    'socket' => [
        'tcp_nodelay' => true,
    ],
    // For more ssl options, please refer to the manual https://php.net/manual/zh/context.ssl.php
    'ssl' => array(
        // Please use absolute path
        'local_cert'                 => '/path/server.cer', // 也可以是crt文件It can also be a crt file
        'local_pk'                   => '/path/server.key',
        'verify_peer'               => false,
        // 'allow_self_signed' => true, //If it is a self-signed certificate, this option needs to be enabled
        //      'ssltransport'=>'tlsv1.3'
    )
);


$http = new Worker(strtr(OUTBOUND,['tcp'=>'http']),$context);
$http->count = 1;
$http->transport  = 'ssl';

$http->onMessage = function($connection, $data)
{

    global $global;
    $_ja3 =  $global->__get('REMOTE_PORT:'.$connection->getRemotePort());
    $connection->send(json_encode($_ja3));
};



// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
