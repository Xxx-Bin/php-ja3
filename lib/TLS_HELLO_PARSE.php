<?php

require_once 'BinaryStream.php';

class TLS_HELLO_PARSE
{


    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    // Last Updated: 2026-03-16
    // Source: IANA TLS ExtensionType Values Registry
    static $tls_extension_type_values = [
        // Standard Extensions (0-61)
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
        "53" => "connection_id_deprecated",
        "54" => "connection_id",
        "55" => "external_id_hash",
        "56" => "external_session_id",
        "57" => "quic_transport_parameters",
        "58" => "ticket_request",
        "59" => "dnssec_chain",
        "60" => "sequence_number_encryption_algorithms",
        "61" => "rrc",
        "62" => "tls_flags",

        // GREASE Values (Reserved for Extensibility Testing) [RFC8701]
        "2570" => "grease_reserved_2570",
        "6682" => "grease_reserved_6682",
        "10794" => "grease_reserved_10794",
        "14906" => "grease_reserved_14906",
        "19018" => "grease_reserved_19018",
        "23130" => "grease_reserved_23130",
        "27242" => "grease_reserved_27242",
        "31354" => "grease_reserved_31354",
        "35466" => "grease_reserved_35466",
        "39578" => "grease_reserved_39578",
        "43690" => "grease_reserved_43690",
        "47802" => "grease_reserved_47802",
        "51914" => "grease_reserved_51914",
        "56026" => "grease_reserved_56026",
        "60138" => "grease_reserved_60138",
        "64250" => "grease_reserved_64250",

        // ECH Extensions
        "64768" => "ech_outer_extensions",
        "65037" => "encrypted_client_hello",

        // Private Use Range Start
        "65280" => "private_use_start",
        "65281" => "renegotiation_info",
        "65282" => "private_use_65282",

        // Legacy/Deprecated Extensions
        "13172" => "next_protocol_negotiation",
        "17513" => "application_settings",
        "30031" => "channel_id_old",
        "30032" => "channel_id",
        "65445" => "quic_transport_parameters_legacy",
        "65486" => "encrypted_server_name",
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


    // Type: application_layer_protocol_negotiation (16)
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

    // Type: key_share (51) - TLS 1.3
    public static function extensions_key_share(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['51'])) {
            $length = $extensions_arr_by_type['51']['length'];
            $offset = $extensions_arr_by_type['51']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_key_share_len' => BinaryStream::uint16,
                ]);

                $key_shares = [];
                $bytes_read = 2;
                $i = 0;

                while ($bytes_read < $length && $i < 100) { // 限制最多 100 个 key shares
                    if ($length - $bytes_read < 4) break;

                    $group = $BinaryStream->unpack(['group' => BinaryStream::uint16]);
                    $key_exchange_len = $BinaryStream->unpack(['len' => BinaryStream::uint16]);

                    $bytes_read += 4;

                    if ($key_exchange_len['len'] > 0 && $bytes_read + $key_exchange_len['len'] <= $length) {
                        $key_exchange = $BinaryStream->unpack([
                            'key_exchange' => [BinaryStream::uint8, $key_exchange_len['len'], 'Unit8ManyToHexStr']
                        ]);

                        $key_shares[] = [
                            'group' => $group['group'],
                            'key_exchange' => $key_exchange['key_exchange'] ?? ''
                        ];
                        $bytes_read += $key_exchange_len['len'];
                    }
                    $i++;
                }

                $ret['tls_tls_handshake_extensions_key_shares'] = $key_shares;
            }
        }

        return $ret;
    }

    // Type: psk_key_exchange_modes (45) - TLS 1.3
    public static function extensions_psk_key_exchange_modes(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['45'])) {
            $length = $extensions_arr_by_type['45']['length'];
            $offset = $extensions_arr_by_type['45']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 1) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_psk_ke_modes_len' => BinaryStream::uint8,
                ]);

                $modes_len = $ret['tls_tls_handshake_extensions_psk_ke_modes_len'] ?? 0;
                if ($modes_len > 0 && $modes_len <= $length - 1) {
                    $ret += $BinaryStream->unpack([
                        'tls_tls_handshake_extensions_psk_ke_modes' => [BinaryStream::uint8, $modes_len],
                    ]);
                }
            }
        }

        return $ret;
    }

    // Type: early_data (42) - TLS 1.3
    public static function extensions_early_data(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['42'])) {
            $length = $extensions_arr_by_type['42']['length'];
            $offset = $extensions_arr_by_type['42']['offset'];
            $BinaryStream->setOffset($offset);

            // early_data 在 ClientHello 中可以为空
            // 在 NewSessionTicket 中包含 max_early_data_size
            if ($length >= 4) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_max_early_data_size' => BinaryStream::uint32,
                ]);
            }

            $ret['tls_tls_handshake_extensions_early_data_present'] = true;
        }

        return $ret;
    }

    // Type: cookie (44) - TLS 1.3
    public static function extensions_cookie(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['44'])) {
            $length = $extensions_arr_by_type['44']['length'];
            $offset = $extensions_arr_by_type['44']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_cookie_len' => BinaryStream::uint16,
                ]);

                $cookie_len = $ret['tls_tls_handshake_extensions_cookie_len'] ?? 0;
                if ($cookie_len > 0 && $cookie_len <= $length - 2) {
                    $ret += $BinaryStream->unpack([
                        'tls_tls_handshake_extensions_cookie' => [BinaryStream::uint8, $cookie_len, 'Unit8ManyToHexStr'],
                    ]);
                }
            }
        }

        return $ret;
    }

    // Type: certificate_authorities (47) - TLS 1.3
    public static function extensions_certificate_authorities(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['47'])) {
            $length = $extensions_arr_by_type['47']['length'];
            $offset = $extensions_arr_by_type['47']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_ca_list_len' => BinaryStream::uint16,
                ]);

                $ca_list_len = $ret['tls_tls_handshake_extensions_ca_list_len'] ?? 0;
                $bytes_read = 2;
                $authorities = [];
                $i = 0;

                while ($bytes_read < $ca_list_len && $i < 50) { // 限制最多 50 个 CA
                    if ($ca_list_len - $bytes_read < 2) break;

                    $dn_len = $BinaryStream->unpack(['len' => BinaryStream::uint16]);
                    $bytes_read += 2;

                    if ($dn_len['len'] > 0 && $bytes_read + $dn_len['len'] <= $ca_list_len) {
                        $dn = $BinaryStream->unpack([
                            'dn' => [BinaryStream::uint8, $dn_len['len'], 'Unit8ManyToHexStr']
                        ]);
                        $authorities[] = $dn['dn'] ?? '';
                        $bytes_read += $dn_len['len'];
                    }
                    $i++;
                }

                $ret['tls_tls_handshake_extensions_authorities'] = $authorities;
            }
        }

        return $ret;
    }

    // Type: compress_certificate (27)
    public static function extensions_compress_certificate(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['27'])) {
            $length = $extensions_arr_by_type['27']['length'];
            $offset = $extensions_arr_by_type['27']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 1) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_cert_compression_algorithms_len' => BinaryStream::uint8,
                ]);

                $algorithms_len = $ret['tls_tls_handshake_extensions_cert_compression_algorithms_len'] ?? 0;
                if ($algorithms_len > 0 && $algorithms_len <= $length - 1) {
                    $count = intval($algorithms_len / 2);
                    $ret += $BinaryStream->unpack([
                        'tls_tls_handshake_extensions_cert_compression_algorithms' => [BinaryStream::uint16, $count],
                    ]);
                }
            }
        }

        return $ret;
    }

    // Type: record_size_limit (28)
    public static function extensions_record_size_limit(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['28'])) {
            $length = $extensions_arr_by_type['28']['length'];
            $offset = $extensions_arr_by_type['28']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_record_size_limit' => BinaryStream::uint16,
                ]);
            }
        }

        return $ret;
    }

    // Type: delegated_credential (34)
    public static function extensions_delegated_credential(&$BinaryStream, &$extensions_arr_by_type)
    {
        $ret = [];
        if (!empty($extensions_arr_by_type['34'])) {
            $length = $extensions_arr_by_type['34']['length'];
            $offset = $extensions_arr_by_type['34']['offset'];
            $BinaryStream->setOffset($offset);

            if ($length >= 2) {
                $ret += $BinaryStream->unpack([
                    'tls_tls_handshake_extensions_delegated_credential_supported_algorithms_len' => BinaryStream::uint16,
                ]);

                $algorithms_len = $ret['tls_tls_handshake_extensions_delegated_credential_supported_algorithms_len'] ?? 0;
                if ($algorithms_len > 0 && $algorithms_len <= $length - 2) {
                    $count = intval($algorithms_len / 2);
                    $ret += $BinaryStream->unpack([
                        'tls_tls_handshake_extensions_delegated_credential_supported_algorithms' => [BinaryStream::uint16, $count],
                    ]);
                }
            }
        }

        return $ret;
    }

}