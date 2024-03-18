<?php
define('TCPDUMP_LISTEN_INTERFACE',1);
use Workerman\Events\EventInterface;
use \Workerman\Worker;

$tcp_data_age = 300;//second
require_once __DIR__ . '/lib/function.php';
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__.'/lib/DataShareServer.php';
require_once __DIR__.'/lib/TLS_FP.php';
require_once __DIR__.'/lib/TLS_HELLO_PARSE.php';
$worker = new DataShareServer('127.0.0.1', 2207);
$global = new GlobalData\Client('127.0.0.1:2207');
$worker = new Worker();
$global_key = [];
$worker->onWorkerStart = function($_worker){
    global $tcp_data_age;
    \Workerman\Timer::add($tcp_data_age,function (){
        global $global;
        global $global_key;
        global $tcp_data_age;
        $t = time();
        while (($v = current($global_key)) && $v<=$t-$tcp_data_age){
            $global->__unset(key($global_key));
            array_shift($global_key);
        }
    });
    //need tshark  3.*
    if(strtoupper(substr(PHP_OS,0,3))==="WIN"){
        $cmd = '"tshark.exe" -i '.TCPDUMP_LISTEN_INTERFACE.'  -f "tcp port 443 and (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3))" -n -l  -T ek -P -V -q ';
    }else{
        $cmd = 'tshark -i '.TCPDUMP_LISTEN_INTERFACE.'  -f "tcp port 443 and (tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3))" -n -l -T ek -P -V -q ';

    }
    $flag = EventInterface::EV_READ;
    $fd = popen($cmd, 'r');
    $data_pack = '';
    Worker::$globalEvent->add($fd, $flag, function ($socket, $check_eof = true) use ($_worker,$fd,&$data_pack) {
        global $flag;
        if (!feof($socket)) {
            $buf = \fread($socket, 65535);
            $buf  = explode("\n",trim($buf));
            foreach ($buf as $k=>$line){
                if( strpos($line,'}}',strlen($line)-2)!==false){

                    $data_pack .= $line;
                    if(strpos(substr($data_pack,0,8),'{"index"',0)!==false){
                        $data_pack  = '';
                        continue;
                    }
                    $source_port = value_by_key_name($data_pack,'tcp_tcp_srcport');

                    $raw_data = strtr(value_by_key_name($data_pack,'tcp_tcp_payload'),[':'=>'']);
                    $data = hex2bin(strtr($raw_data,[':'=>'']));
                    $tls = TLS_HELLO_PARSE::get($data);
                    $tls_pf['client'] = TLS_FP::init(['layers'=>['ip'=>['ip_ip_proto'=>value_by_key_name($data_pack,'ip_ip_proto')],'tls'=>$tls]])->ret();


                    global $global;
                    global $global_key;
                    $global_key['REMOTE_PORT:'.$source_port] = time();
                    $global->__set('REMOTE_PORT:'.$source_port,$tls_pf);
                    $data_pack  = '';
                }else{
                    $data_pack .= $line;
                }
            }

        } else {
            Worker::$globalEvent->del($socket, $flag);
            fclose($fd);
            echo 'close';

        }
    });


};

// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
