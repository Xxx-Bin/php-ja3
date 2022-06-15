<?php

define('TCPDUMP_LISTEN_INTERFACE',1);

use Workerman\Connection\AsyncTcpConnection;
use \Workerman\Worker;
use \Workerman\WebServer;

require_once __DIR__.'/vendor/autoload.php';
require_once __DIR__.'/lib/BinaryStream.php';
require_once __DIR__.'/lib/Ja3.php';
require_once __DIR__.'/lib/DataShareServer.php';
$worker = new DataShareServer('127.0.0.1', 2207);
$global = new GlobalData\Client('127.0.0.1:2207');
$global_key = [];

$worker = new Worker();
$worker->count = 1;

$data_age = 60;//second
$worker->onConnect = function ($connection) {


};
$worker->onMessage = function ($connection, $data) {
    var_dump(implode(' ', unpack('C*', $data)));
};


$worker->onWorkerStart = function ($_worker) use ($worker) {
    global $data_age;
    \Workerman\Timer::add($data_age,function (){
        global $global;
        global $global_key;
        global $data_age;
        $t = time();
        while (($v = current($global_key)) && $v<=$t-$data_age){
            $global->__unset(key($global_key));
            array_shift($global_key);
        }
    });
    $read_file_head = false;
    $buffer = '';
    $package_len = 0;
    $fp = popen('tcpdump -i '.TCPDUMP_LISTEN_INTERFACE.' \'tcp port 443 and (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3))\'  -U -lnNO   -w -',
        'r');
    $worker->onClose = function () use ($fp) {
        fclose($fp);
    };
    stream_set_blocking($fp,false);

    Worker::$globalEvent->add($fp, Workerman\Events\EventInterface::EV_READ,
        function ($socket) use ($fp, &$read_file_head, &$buffer, &$package_len) {
            if (!feof($fp)) {
                $data = fgets($fp, 1024);
                if(empty($data)){
                    return;
                }
                if (!$read_file_head) {
                    // The per-file header length is 24 octets.
                    $read_file_head = substr($data, 0, 4) == "\xa1\xb2\xc3\xd4"
                        || substr($data, 0, 4) == "\xd4\xc3\xb2\xa1";
                    $data = substr($data, 24);
                }

                // The per-packet header length is 16 octets.
                $buffer .= $data;
                $data = null;
                if ($package_len == 0) {
                    if (strlen($buffer) >= 16) {
                        $package_len = substr($buffer, 8, 4);
                        $package_len = (unpack('L', $package_len))[1];
                    }
                }

                if (strlen($buffer) - 16 >= $package_len) {
                    // mac frame
//                    $package_data = substr($buffer,16,$package_len);
                    $soure_port = unpack('nn', substr($buffer, 16 + 14 + 20, 2));
                    $destination_port = unpack('nn', substr($buffer, 16 + 14 + 20 + 2, 2));

                    //  per-packet header 16 , mac frame header 14 ,ip header 20,tcp header ?
                    $offset = ord(substr($buffer, 16 + 14 + 20 + 12, 1))/16*4;
                    $ja3 = Ja3::get(substr($buffer, 16 + 14 + 20 + $offset, $package_len));
                    global $global;
                    global $global_key;
                    $global_key['REMOTE_PORT:'.$soure_port['n']] = time();
                    $global->__set('REMOTE_PORT:'.$soure_port['n'],$ja3);
                    // next paackage
                    $buffer = substr($buffer, 16 + $package_len);
                    $package_len = 0;
                }

            } else {
                echo 'exit';
                exit;
            }


        });
};
// 如果不是在根目录启动，则运行runAll方法
if (!defined('GLOBAL_START')) {
    Worker::runAll();
}