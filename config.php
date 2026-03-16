<?php
/**
 * 配置文件
 * 返回配置数组
 */

return [
    'ssl' => [
        'local_cert'  => '/path/server.cer',
        'local_pk'    => '/path/server.key',
        'verify_peer' => false,
//        'allow_self_signed' => true,
//        'ssltransport' => 'tlsv1.3',
        'alpn_protocols' => 'h2',
    ],
    'server' => [
        'listen' => 'ssl://127.0.0.1:9765',
        'count' => 1,
    ],
    'global_data' => [
        'address' => '127.0.0.1:2207',
    ],
    'proxy' => [
        'inbound' => 'tcp://0.0.0.0:9763',
        'outbound' => 'tcp://127.0.0.1:443',
        'inbound_ex' => 'tcp://0.0.0.0:9764',
        'outbound_ex' => 'tcp://127.0.0.1:9765',
    ],
];
