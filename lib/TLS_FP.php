<?php


class TLS_FP
{
    public static $GREASE_TABELE = [
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    ];

    public static $ssl_version = [
//        0x0100 => "s1",// SSL 1.0 never existed
        0x0200 => "s2",//SSL 2.0
        0x0300 => "s3",//SSL 3.0
        0x0301 => "10",//TLS 1.0
        0x0302 => "11",//TLS 1.1
        0x0303 => "12",//TLS 1.2
        0x0304 => "13",//TLS 1.3
        0xfeff => "d1",//DTLS 1.0
        0xfefd => "d2",//DTLS 1.2
        0xfefc => "d3",//DTLS 1.3
        0x00 => null,
    ];
    public $hello_data;

    private $cache;

    public static function init($hello_data)
    {
        $obj = new self();
        $obj->hello_data = $hello_data;
        return $obj;
    }

    public function ret()
    {
        $JA3 =  $this->GET_JA3();
        $JA4 =  $this->GET_JA4();

        return array_merge($JA3,$JA4);
    }

    public function ret_by_server()
    {
        $JA3 =  $this->GET_JA3S();
        $JA4 =  $this->GET_JA4S();
        return array_merge($JA3,$JA4);
    }




    public  function GET_JA3(){
        $tls = $this->hello_data['layers']['tls'];
        $ja3_arr = [];
        $ja3_arr[] = is_numeric($tls['tls_tls_handshake_version'])?$tls['tls_tls_handshake_version']:hexdec($tls['tls_tls_handshake_version']);

        $cipher_suites = $this->get_tls_ext_data('tls_tls_handshake_ciphersuite',true,true);
        $ja3_arr[] = empty($cipher_suites)?'':implode('-', $cipher_suites);

        $extensions_type_arr = $this->get_tls_ext_data('tls_tls_handshake_extension_type',true);

        $ja3_arr[] = empty($extensions_type_arr) ? '' : implode('-', $extensions_type_arr);


        $EllipticCurve = $this->get_tls_ext_data('tls_tls_handshake_extensions_supported_group',true,true);
        $ja3_arr[] = empty($EllipticCurve) ? '' : implode('-',
            $EllipticCurve);


        $EllipticCurvePointFormat = $this->get_tls_ext_data('tls_tls_handshake_extensions_ec_point_format',true);
        $ja3_arr[] = empty($EllipticCurvePointFormat) ? '' : implode('-',
            $EllipticCurvePointFormat);
        $ja3_str = implode(',', $ja3_arr);
        return [
            'ja3' => md5($ja3_str),
            'ja3_str' => $ja3_str,

        ];
    }

    public function GET_JA3S()
    {
        $tls = $this->hello_data['layers']['tls'];
        $ja3_arr = [];
        $ja3_arr[] = is_numeric($tls['tls_tls_handshake_version'])?$tls['tls_tls_handshake_version']:hexdec($tls['tls_tls_handshake_version']);

        $cipher_suites = $this->get_tls_ext_data('tls_tls_handshake_ciphersuite',true,true);
        $ja3_arr[] = empty($cipher_suites)?'':implode('-', $cipher_suites);

        $extensions_type_arr = $this->get_tls_ext_data('tls_tls_handshake_extension_type',true);

        $ja3_arr[] = empty($extensions_type_arr) ? '' : implode('-', $extensions_type_arr);


        $ja3_str = implode(',', $ja3_arr);
        return [
            'ja3s' => md5($ja3_str),
            'ja3s_str' => $ja3_str,

        ];
    }


    public  function GET_JA4()
    {

        $tls = $this->hello_data['layers']['tls'];

        $ja4_a = [
            'protocol' => 't',
            'max_supported_tls_version' => 00,
            'SNI' => 'i',
            'number_of_cipher_suites' => 0, // GREASE_TABELE ignore
            'number_of_extensions' => 0, // GREASE_TABEL,SNI ignore
            'first_ALPN' => 'i',// 00 if no alpn
        ];
        //ja4_a protocol ,tcp = 't',quic = "q"
        $ja4_a['protocol'] = [6 => 't', '17' => 'q'][$this->hello_data['layers']['ip']['ip_ip_proto']];

        //ja4_a TLS version ,1.2 = 12, 1.3 = 13
        $tls_version = 0;
        $tls_tls_handshake_extensions_supported_version = $this->get_tls_ext_data('tls_tls_handshake_extensions_supported_version',true,true);

        if (!empty($tls_tls_handshake_extensions_supported_version)) {

            $tls_version = max($tls_tls_handshake_extensions_supported_version);
        }else{
            $tls_version = is_numeric($tls['tls_tls_handshake_version'])?$tls['tls_tls_handshake_version']:hexdec($tls['tls_tls_handshake_version']);
        }

        $ja4_a['max_supported_tls_version'] = sprintf('%02d',
            empty($tls_version) ? 0 : TLS_FP::$ssl_version[$tls_version]);

        //ja4_a SNI
        $ja4_a['SNI'] = [
            0 => 'd',
            null => 'i',
        ][isset($tls['tls_tls_handshake_extensions_server_name_type']) ? $tls['tls_tls_handshake_extensions_server_name_type'] : null];


        // GREASE_TABEL ignore
        $cipher_suites = $this->get_tls_ext_data('tls_tls_handshake_ciphersuite',true,true);

        $ja4_a['number_of_cipher_suites'] = count($cipher_suites);
        $ja4_a['number_of_cipher_suites'] = sprintf('%02d',
            $ja4_a['number_of_cipher_suites'] > 99 ? 99 : $ja4_a['number_of_cipher_suites']);

        //ja4_a number_of_extensions

        $extensions_type_arr = $this->get_tls_ext_data('tls_tls_handshake_extension_type',true);
        // GREASE_TABEL,SNI,ALPN  ignore
        $extensions_type_arr_for_order = array_diff($extensions_type_arr, [0x0000, 0x0010]);
        $ja4_a['number_of_extensions'] = count($extensions_type_arr);
        $ja4_a['number_of_extensions'] = sprintf('%02d',
            $ja4_a['number_of_extensions'] > 99 ? 99 : $ja4_a['number_of_extensions']);


        //ja4_a first_alpn
        $first_ALPN = '00';
        $tls_tls_handshake_extensions_alpn_str = $this->get_tls_ext_data('tls_tls_handshake_extensions_alpn_str');
        if (!empty($tls_tls_handshake_extensions_alpn_str)) {

            $first_ALPN = current($tls_tls_handshake_extensions_alpn_str);
            if (strlen($first_ALPN) > 2) {
                $first_ALPN = substr($first_ALPN, 0, 1).substr($first_ALPN, -1, 1);
            } else {
                if (strlen($first_ALPN) > 127) {
                    $first_ALPN = '99';
                }
            }
        }
        $ja4_a['first_ALPN'] = sprintf('%02s', empty($first_ALPN) ? 0 : $first_ALPN);


        // ja4_b  hash order cipher_suites
        // ja4_b_o origin  cipher_suites
        // ja4_b_r hash sort  cipher_suites
        // ja4_b_ro  hash origin  cipher_suites
        $ja4_b_original = array_map(function ($v) {
            return sprintf('%04x', $v);
        }, $cipher_suites);
        $ja4_b_order = $ja4_b_original;
        sort($ja4_b_order);


        //
        $ja4_c_extensions_original = array_map(function ($v) {
            return sprintf('%04x', $v);
        }, $extensions_type_arr);
        $ja4_c_extensions_order = array_map(function ($v) {
            return sprintf('%04x', $v);
        }, $extensions_type_arr_for_order);
        sort($ja4_c_extensions_order);


        $ja4_c_signature_algorithms = [];
        $signature_algorithms = $this->get_tls_ext_data('tls_tls_handshake_sig_hash_alg',true,true);
        if(!empty($signature_algorithms)){

            if(array_search('34',$tls['tls_tls_handshake_extension_type'])!==false
                && is_array($tls['tls_tls_handshake_sig_hash_alg_len'])){
                // ignore exitension delegated_credential(34)
                if(array_search('13',$tls['tls_tls_handshake_extension_type']) > array_search('34',$tls['tls_tls_handshake_extension_type'])){
                    array_splice($signature_algorithms,0,$tls['tls_tls_handshake_sig_hash_alg_len']['0']/2);
                }else{
                    array_splice($signature_algorithms,$tls['tls_tls_handshake_sig_hash_alg_len']['0']/2,$tls['tls_tls_handshake_sig_hash_alg_len']['1']/2);
                }
            }

            $ja4_c_signature_algorithms = array_map(function ($v) {
                return sprintf('%04x', $v);
            }, $signature_algorithms);
        }

        $ja4_c_original = implode(',',$ja4_c_extensions_original).'_'.implode(',',$ja4_c_signature_algorithms);
        $ja4_c_order = implode(',',$ja4_c_extensions_order).'_'.implode(',',$ja4_c_signature_algorithms);

        $ja4_a = implode('',$ja4_a);

        $ja4 = implode('_', [$ja4_a,TLS_FP::hash_first_12_chart($ja4_b_order),TLS_FP::hash_first_12_chart($ja4_c_order)]);
        $ja4_o = implode('_', [$ja4_a,TLS_FP::hash_first_12_chart($ja4_b_original),TLS_FP::hash_first_12_chart($ja4_c_original)]);
        $ja4_r = implode('_', [$ja4_a,implode(',',$ja4_b_order),$ja4_c_order]);
        $ja4_ro = implode('_', [$ja4_a,implode(',',$ja4_b_original),$ja4_c_original]);


        return [
            'ja4' => $ja4,// ja4_a + hash(sorted_ciphers) + hash(sorted_extensions)
            'ja4_o' => $ja4_o,//ja4_a + hash(original_ciphers) + hash(original_extensions)
            'ja4_r' => $ja4_r,//ja4_a + sorted_ciphers + sorted_extensions
            'ja4_ro' => $ja4_ro,//ja4_a + original_ciphers + original_extensions

        ];

    }

    public  function GET_JA4S()
    {

        $tls = $this->hello_data['layers']['tls'];

        $ja4s_a = [
            'protocol' => 't',
            'max_supported_tls_version' => 00,
            'number_of_extensions' => 0, // GREASE_TABEL,SNI ignore
            'first_ALPN' => 'i',// 00 if no alpn
        ];
        //ja4s_a protocol ,tcp = 't',quic = "q"
        $ja4s_a['protocol'] = [6 => 't', '17' => 'q'][$this->hello_data['layers']['ip']['ip_ip_proto']];

        //ja4s_a TLS version ,1.2 = 12, 1.3 = 13
        $tls_version = 0;
        $tls_tls_handshake_extensions_supported_version = $this->get_tls_ext_data('tls_tls_handshake_extensions_supported_version',true,true);

        if (!empty($tls_tls_handshake_extensions_supported_version)) {

            $tls_version = max($tls_tls_handshake_extensions_supported_version);
        }else{
            $tls_version = is_numeric($tls['tls_tls_handshake_version'])?$tls['tls_tls_handshake_version']:hexdec($tls['tls_tls_handshake_version']);
        }

        $ja4s_a['max_supported_tls_version'] = sprintf('%02d',
            empty($tls_version) ? 0 : TLS_FP::$ssl_version[$tls_version]);


        //ja4s_a number_of_extensions

        $extensions_type_arr = $this->get_tls_ext_data('tls_tls_handshake_extension_type',true);
        // GREASE_TABEL,SNI,ALPN  ignore
        $extensions_type_arr_for_order = array_diff($extensions_type_arr, [0x0000, 0x0010]);
        $ja4s_a['number_of_extensions'] = count($extensions_type_arr);
        $ja4s_a['number_of_extensions'] = sprintf('%02d',
            $ja4s_a['number_of_extensions'] > 99 ? 99 : $ja4s_a['number_of_extensions']);


        //ja4_a first_alpn
        $first_ALPN = '00';
        $tls_tls_handshake_extensions_alpn_str = $this->get_tls_ext_data('tls_tls_handshake_extensions_alpn_str');
        if (!empty($tls_tls_handshake_extensions_alpn_str)) {

            $first_ALPN = current($tls_tls_handshake_extensions_alpn_str);
            if (strlen($first_ALPN) > 2) {
                $first_ALPN = substr($first_ALPN, 0, 1).substr($first_ALPN, -1, 1);
            } else {
                if (strlen($first_ALPN) > 127) {
                    $first_ALPN = '99';
                }
            }
        }
        $ja4s_a['first_ALPN'] = sprintf('%02s', empty($first_ALPN) ? 0 : $first_ALPN);

// GREASE_TABEL ignore
        $cipher_suites = $this->get_tls_ext_data('tls_tls_handshake_ciphersuite',true,true);
        // ja4s_b  hash order cipher_suites
        // ja4s_b_o origin  cipher_suites
        // ja4s_b_r hash sort  cipher_suites
        // ja4s_b_ro  hash origin  cipher_suites
        $ja4_b_original = array_map(function ($v) {
            return sprintf('%04x', $v);
        }, $cipher_suites);



        //
        $ja4_c_extensions_original = array_map(function ($v) {
            return sprintf('%04x', $v);
        }, $extensions_type_arr);





        $ja4_c_original = implode(',',$ja4_c_extensions_original);


        $ja4s_a = implode('',$ja4s_a);


        $ja4s = implode('_', [$ja4s_a,implode(',',$ja4_b_original),TLS_FP::hash_first_12_chart($ja4_c_original)]);

        $ja4_ro = implode('_', [$ja4s_a,implode(',',$ja4_b_original),$ja4_c_original]);


        return [
            'ja4s' => $ja4s,// ja4_a + hash(sorted_ciphers) + hash(sorted_extensions)

            'ja4_ro' => $ja4_ro,//ja4_a + original_ciphers + original_extensions

        ];

    }


    public static function hash_first_12_chart($text)
    {
        is_array($text) && $text = implode(',',$text);
        return substr(hash('sha256',$text),0,12);
    }

    public static function get_tls_extensions_data(&$tls,$k,$filter = false,$HexDec = false)
    {
        $ret = [];
        if(isset($tls[$k])){
            $ret = $tls[$k];
            is_array($ret) || $ret = [$tls[$k]];
            if($HexDec){
                array_walk($ret, function (&$v) {
                    $v = is_numeric($v) ? $v : hexdec($v);
                });
            }
            if($filter){
                $ret = array_diff($ret,self::$GREASE_TABELE);
            }

        }


        return $ret;
    }

    public function get_tls_ext_data($k,$filter=false,$HexDec=false)
    {
        if(isset($this->cache[$k])){
            return $this->cache[$k];
        }
        return  $this->cache[$k] = self::get_tls_extensions_data($this->hello_data['layers']['tls'],$k,$filter,$HexDec);
    }


    public static function full_to_ja3($ja3_full){
        $ja3_arr = explode(',',$ja3_full);
        array_walk($ja3_arr,function(&$v){
            $v = explode('-',$v);
            if(!is_array($v)){
                $v = [$v];
            }
            $v = array_diff($v,self::$GREASE_TABELE);
            $v = implode('-',$v);
        });
        $str = implode(',',$ja3_arr);
        $hash = md5($str);
        return [
            'ja3_hash'=>$hash,
            'ja3_str'=>$str,
        ];


    }










}