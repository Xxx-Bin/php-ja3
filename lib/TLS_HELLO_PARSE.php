<?php

require_once 'BinaryStream.php';

class TLS_HELLO_PARSE
{


    //https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    // last update 2023-12-14
    //devtools run js
    // let arr=[];$('#table-tls-extensiontype-values-1 tr').map((e,v,item)=>{let id=$(v).children('td').eq(0).text();let name=$(v).children('td').eq(1).text().replace(/\([\S\s]*\)/,'');if(name&&!/Reserved|Unassigned/.test(name)){arr.push('"'+id+'"=>"'+name+'"')}});arr.join(',')
    static $tls_extension_type_values = [
        "0" => "server_name",
        "1" => "max_fragment_length",
        "2" => "client_certificate_url",
        "3" => "trusted_ca_keys",
        "4" => "truncated_hmac",
        "5" => "status_request",
        "6" => "user_mapping",
        "7" => "client_authz",
        "8" => "server_authz",
        "9" => "cert_type",
        "10" => "supported_groups",
        "11" => "ec_point_formats",
        "12" => "srp",
        "13" => "signature_algorithms",
        "14" => "use_srtp",
        "15" => "heartbeat",
        "16" => "application_layer_protocol_negotiation",
        "17" => "status_request_v2",
        "18" => "signed_certificate_timestamp",
        "19" => "client_certificate_type",
        "20" => "server_certificate_type",
        "21" => "padding",
        "22" => "encrypt_then_mac",
        "23" => "extended_master_secret",
        "24" => "token_binding",
        "25" => "cached_info",
        "26" => "tls_lts",
        "27" => "compress_certificate",
        "28" => "record_size_limit",
        "29" => "pwd_protect",
        "30" => "pwd_clear",
        "31" => "password_salt",
        "32" => "ticket_pinning",
        "33" => "tls_cert_with_extern_psk",
        "34" => "delegated_credential",
        "35" => "session_ticket",
        "36" => "TLMSP",
        "37" => "TLMSP_proxying",
        "38" => "TLMSP_delegate",
        "39" => "supported_ekt_ciphers",
        "41" => "pre_shared_key",
        "42" => "early_data",
        "43" => "supported_versions",
        "44" => "cookie",
        "45" => "psk_key_exchange_modes",
        "47" => "certificate_authorities",
        "48" => "oid_filters",
        "49" => "post_handshake_auth",
        "50" => "signature_algorithms_cert",
        "51" => "key_share",
        "52" => "transparency_info",
        "53" => "connection_id",
        "54" => "connection_id",
        "55" => "external_id_hash",
        "56" => "external_session_id",
        "57" => "quic_transport_parameters",
        "58" => "ticket_request",
        "59" => "dnssec_chain",
        "60" => "sequence_number_encryption_algorithms",
        "61" => "rrc",
        "64768" => "ech_outer_extensions",
        "65037" => "encrypted_client_hello",
        "65281" => "renegotiation_info",

        "13172"=>"next_protocol_negotiation",/* 0x3374 */
        "17513"=>"application_settings",/* draft-vvv-tls-alps-01, temporary value used in BoringSSL implementation */
        "30031"=>"channel_id_old   ",/* 0x754f */
        "30032"=>"channel_id ",/* 0x7550 */
        "65445"=>"quic_transport_parameters",/* 0xffa5 draft-ietf-quic-tls-13 */
        "65486"=>"encrypted_server_name",/* 0xffce draft-ietf-tls-esni-01 */
    ];

    public static function get($tcp_data)
    {

        $BinaryStream = new BinaryStream();
        $BinaryStream->setContent($tcp_data);
        $ret = [];
        $ja3_arr = [];
        $ret += $BinaryStream->unpack([
            'tls_tls_record_content_type' => BinaryStream::uint8,
        ]);
//    echo $ret['tls_tls_record_content_type'].PHP_EOL;
        if ($ret['tls_tls_record_content_type'] == 22) {

            $ret += $BinaryStream->unpack([
                'tls_tls_record_version' => BinaryStream::uint16,
                'tls_tls_record_length' => BinaryStream::uint16,
                'tls_tls_handshake_type' => BinaryStream::uint8,
                'tls_tls_handshake_length' => [BinaryStream::uint8, 3, 'Unit8ManyToDec'],
                'tls_tls_handshake_version' => BinaryStream::uint16,
                'tls_tls_handshake_random' => [BinaryStream::uint8, 32, 'Unit8ManyToHexStr'],
                'tls_tls_handshake_session_id_length' => BinaryStream::uint8,
            ]);
            if ($ret['tls_tls_handshake_session_id_length'] > 0) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_session_id' => [
                        BinaryStream::uint8,
                        $ret['tls_tls_handshake_session_id_length'],
                        'Unit8ManyToHexStr',
                    ],
                ]);
            }
            //client hello
            if ($ret['tls_tls_handshake_type'] == 1) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_cipher_suites_length' => BinaryStream::uint16,
                ]);
                $ciphersuites_count = $ret['tls_tls_handshake_cipher_suites_length'] / 2;
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_ciphersuite' => [BinaryStream::uint16, $ciphersuites_count],
                    'tls_tls_handshake_comp_methods_length' => BinaryStream::uint8,
                    'tls_tls_handshake_comp_method' => BinaryStream::uint8,
                    'tls_tls_handshake_extension_len' => BinaryStream::uint16,
                ]);

            } else {
                if ($ret['tls_tls_handshake_type'] == 2) {
                    // server hello
                    $ret += $BinaryStream->unpack([
                        'tls_tls_handshake_ciphersuite' => [BinaryStream::uint16, 1],
                        'tls_tls_handshake_comp_method' => BinaryStream::uint8,
                        'tls_tls_handshake_extension_len' => BinaryStream::uint16,
                    ]);
                } else {
                    return false;
                }
            }


            $extensions_length = $ret['tls_tls_handshake_extension_len'];
            $extensions = [];
            $j = 0;

            for ($i = 0; $i < $extensions_length; $j++) {
                $extensions[$j] = $BinaryStream->unpack([
                    'type' => BinaryStream::uint16,
                    'length' => BinaryStream::uint16,
                ]);

                $offset = $BinaryStream->getOffset();
                $extensions[$j]['offset'] = $offset;
                $length = $extensions[$j]['length'];
                $i += 4 + $length;
                $BinaryStream->setOffset($offset + $length);
            }


            $ret['tls_tls_handshake_extension_type'] = array_column($extensions, 'type');
            $extensions_arr_by_type = array_column($extensions, null, 'type');

            foreach ($ret['tls_tls_handshake_extension_type'] as $type){
                if(isset(self::$tls_extension_type_values[$type])){
                    $func = 'extensions_'.self::$tls_extension_type_values[$type];
                    if(method_exists(__CLASS__,$func)){

//                        $ret+= call_user_func_array(__CLASS__.'::'.$func,[$BinaryStream, $extensions_arr_by_type]);
                        $ret+= ( __CLASS__.'::'.$func)($BinaryStream, $extensions_arr_by_type);
                    }
                    
                    
                }
                
            }

//            //Type: supported_groups (10)
//            $ret += self::extensions_supported_groups($BinaryStream, $extensions_arr_by_type);
//            $EllipticCurve = &$ret['tls_tls_handshake_extensions_supported_group'];
//
//
//            //Type: ec_point_formats (11)
//            $ret += self::extensions_ec_point_formats($BinaryStream, $extensions_arr_by_type);
//            $EllipticCurvePointFormat = &$ret['tls_tls_handshake_extensions_ec_point_format'];
//
//
//            //  Extension: signature_algorithms (13)
//            $ret += self::extensions_signature_algorithms($BinaryStream, $extensions_arr_by_type);
//            $SignatureHashAlgorithm = &$ret['tls_tls_handshake_sig_hash_alg'];
//
//
//            // Extension: server_name (0)
//            $ret += self::extensions_server_name($BinaryStream, $extensions_arr_by_type);
//
//            // Type: supported_versions (43)
//            $ret += self::extensions_supported_versions($BinaryStream, $extensions_arr_by_type);
//
//            //Type: application_layer_protocol_negotiation (16)
//            $ret += self::extensions_application_layer_protocol_negotiation($BinaryStream, $extensions_arr_by_type);
//
//
//            //Type: status_request (5)
//            $ret += self::extensions_status_request($BinaryStream, $extensions_arr_by_type);
//
//            //Type: renegotiation_info (65281)
//            $ret += self::extensions_renegotiation_info($BinaryStream, $extensions_arr_by_type);
//
//            //Type: psk_key_exchange_modes (45)
//
//            $ret += self::extensions_psk_key_exchange_modes($BinaryStream, $extensions_arr_by_type);
//
//            //Type: application_settings (17513)
//            $ret += self::extensions_application_settings($BinaryStream, $extensions_arr_by_type);
//
//
//            //Type: encrypted_client_hello (65037)
//            $ret += self::extension_encrypted_client_hello($BinaryStream, $extensions_arr_by_type);
//
//
//            //Type: compress_certificate (27)
//            $ret += self::extensions_compress_certificate($BinaryStream, $extensions_arr_by_type);
//
//            //Type: key_share (51)
//            $ret += self::extensions_key_share($BinaryStream, $extensions_arr_by_type);


            return $ret;
        } else {
            return false;
        }

        return false;
    }

    public static function extensions_supported_groups(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];

        if (!empty($extensions_arr_by_type['10'])) {
            $length = $extensions_arr_by_type['10']['length'];
            $offset = $extensions_arr_by_type['10']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 4) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_supported_groups_length' => BinaryStream::uint16,
                ]);
                $cnt = $length / 2 - 1;
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_supported_group' => [BinaryStream::uint16, $cnt],
                ]);


            }
        }

        return $ret;
    }

    public static function extensions_ec_point_formats(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];

        if (!empty($extensions_arr_by_type['11'])) {
            $length = $extensions_arr_by_type['11']['length'];
            $offset = $extensions_arr_by_type['11']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_ec_point_formats_length' => BinaryStream::uint8,
                ]);
                $cnt = $length - 1;
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_ec_point_format' => [BinaryStream::uint8, $cnt],
                ]);

            }
        }

        return $ret;
    }

    public static function extensions_signature_algorithms(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];

        if (!empty($extensions_arr_by_type['13'])) {
            $length = $extensions_arr_by_type['13']['length'];
            $offset = $extensions_arr_by_type['13']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $cnt = ($length - 2) / 2;
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_sig_hash_alg_len' => BinaryStream::uint16,
                ]);
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_sig_hash_alg' => [BinaryStream::uint16, $cnt],
                ]);
            };
        }

        return $ret;
    }

    public static function extensions_server_name(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['0'])) {
            $length = $extensions_arr_by_type['0']['length'];
            $offset = $extensions_arr_by_type['0']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_server_name_list_len' => BinaryStream::uint16,
                    'tls_tls_handshake_extensions_server_name_type' => BinaryStream::uint8,
                    'tls_tls_handshake_extensions_server_name_len' => BinaryStream::uint16,
                ]);
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_server_name' => [
                        BinaryStream::char,
                        $ret['tls_tls_handshake_extensions_server_name_len'],
                    ],
                ]);


            }

        }

        return $ret;
    }


    public static function extensions_supported_versions(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['43'])) {
            $length = $extensions_arr_by_type['43']['length'];
            $offset = $extensions_arr_by_type['43']['offset'];
            if ($length >= 2) {
                $BinaryStream->setOffset($offset);
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_supported_versions_len' => BinaryStream::uint8,
                ]);

                if ($ret['tls_tls_handshake_extensions_supported_versions_len'] > 0) {
                    $cnt = ($ret['tls_tls_handshake_extensions_supported_versions_len']) / 2;
                    $BinaryStream->setOffset($offset + 1);
                    $ret += $BinaryStream->unpack([
                        'tls_tls_handshake_extensions_supported_version' => [BinaryStream::uint16, $cnt],
                    ]);
                }

            }


        }

        return $ret;
    }


    //Type: application_layer_protocol_negotiation (16)
    public static function extensions_application_layer_protocol_negotiation(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['16'])) {
            $length = $extensions_arr_by_type['16']['length'];
            $offset = $extensions_arr_by_type['16']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_alpn_len' => BinaryStream::uint16,
                ]);

                if ($ret['tls_tls_handshake_extensions_alpn_len'] > 0) {
                    $tls_tls_handshake_extensions_alpn_str_len = [];
                    $tls_tls_handshake_extensions_alpn_str = [];

                    $i = 0;
                    $l = 0;
                    do {
                        $tls_tls_handshake_extensions_alpn_str_len += $BinaryStream->unpack([
                            $i => BinaryStream::uint8,
                        ]);
                        if ($tls_tls_handshake_extensions_alpn_str_len[$i] > 0) {
                            $tls_tls_handshake_extensions_alpn_str += $BinaryStream->unpack([
                                $i => [BinaryStream::char, $tls_tls_handshake_extensions_alpn_str_len[$i]],
                            ]);
                        } else {
                            break;
                        }
                        $l += 1 + $tls_tls_handshake_extensions_alpn_str_len[$i];
                        $i++;

                    } while ($l < $ret['tls_tls_handshake_extensions_alpn_len']);
                    $ret['tls_tls_handshake_extensions_alpn_str_len'] = $tls_tls_handshake_extensions_alpn_str_len;
                    $ret['tls_tls_handshake_extensions_alpn_str'] = $tls_tls_handshake_extensions_alpn_str;

                }


            }

        }

        return $ret;
    }


    private static function add_item_sig_hash()
    {
        
    }


}