<?php
function get_ja3_from_tshark_hello($hello_data){
    $GREASE_TABELE = [
        2570,//(0x0A0A)
        6682,//(0x1A1A)
        10794,//(0x2A2A)
        14906,//(0x3A3A)
        19018,//(0x4A4A)
        23130,//(0x5A5A)
        27242,//(0x6A6A)
        31354,//(0x7A7A)
        35466,//(0x8A8A)
        39578,//(0x9A9A)
        43690,//(0xAAAA)
        47802,//(0xBABA)
        51914,//(0xCACA)
        56026,//(0xDADA)
        60138,//(0xEAEA)
        64250,//(0xFAFA)
    ];
    $tls = $hello_data['layers']['tls'];
    $ja3_arr = [];
    $ja3_arr[] = hexdec($tls['tls_tls_handshake_version']);

    array_walk($tls['tls_tls_handshake_ciphersuite'],function (&$v){
        $v = is_numeric($v)?$v:hexdec($v);
    });
    $ja3_arr[] = empty($tls['tls_tls_handshake_ciphersuite'])?'':implode('-',
        $tls['tls_tls_handshake_ciphersuite'] = array_diff($tls['tls_tls_handshake_ciphersuite'],
            $GREASE_TABELE));

    $extensions_type_arr = $tls['tls_tls_handshake_extension_type'];

    $ja3_arr[] = empty($extensions_type_arr) ? '' : implode('-',
        array_diff($extensions_type_arr, $GREASE_TABELE));


    $EllipticCurve = $tls['tls_tls_handshake_extensions_supported_group'];
    array_walk($EllipticCurve,function (&$v){
        $v = is_numeric($v)?$v:hexdec($v);
    });
    $ja3_arr[] = empty($EllipticCurve) ? '' : implode('-',
        array_diff($EllipticCurve, $GREASE_TABELE));


    $EllipticCurvePointFormat = is_array($tls['tls_tls_handshake_extensions_ec_point_format'])?$tls['tls_tls_handshake_extensions_ec_point_format']:[$tls['tls_tls_handshake_extensions_ec_point_format']];
    $ja3_arr[] = empty($EllipticCurvePointFormat) ? '' : implode('-',
        array_diff($EllipticCurvePointFormat, $GREASE_TABELE));
    $ja3_str = implode(',', $ja3_arr);
    return [
        'ja3_hash' => md5($ja3_str),
        'ja3_str' => $ja3_str,

    ];
}

function ja3_full_to_ja3_hash($ja3_full){
    $GREASE_TABELE = [
        2570,//(0x0A0A)
        6682,//(0x1A1A)
        10794,//(0x2A2A)
        14906,//(0x3A3A)
        19018,//(0x4A4A)
        23130,//(0x5A5A)
        27242,//(0x6A6A)
        31354,//(0x7A7A)
        35466,//(0x8A8A)
        39578,//(0x9A9A)
        43690,//(0xAAAA)
        47802,//(0xBABA)
        51914,//(0xCACA)
        56026,//(0xDADA)
        60138,//(0xEAEA)
        64250,//(0xFAFA)
    ];
    $ja3_arr = explode(',',$ja3_full);
    array_walk($ja3_arr,function(&$v) use ($GREASE_TABELE){
        $v = explode('-',$v);
        if(!is_array($v)){
            $v = [$v];
        }
        $v = array_diff($v,$GREASE_TABELE);
        $v = implode('-',$v);
    });
    $str = implode(',',$ja3_arr);
    $hash = md5($str);
    return [
        'ja3_hash'=>$hash,
        'ja3_str'=>$str,
    ];
}

function value_by_key_name($data_pack,$key_name){

    if(($offset = strpos($data_pack,'"'.$key_name.'":"',0))
        && ($offset = $offset + strlen('"'.$key_name.'":"'))
        && ($end = strpos($data_pack,'"',$offset))){
        return substr($data_pack,$offset,$end-$offset);
    }
    return false;
}