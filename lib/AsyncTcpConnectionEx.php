<?php

namespace Workerman\Connection;

class AsyncTcpConnectionEx extends AsyncTcpConnection
{
    public $LocalPort = null;
    public $MEXT_REMOTE_PORT = null;
    public $h2Parser = null;
    public $h2Driver = null;
    public $tls_fp_client = null;
    public $tls_fp_server = null;
    public $h2_fp_complete = null;
    public $h2_ping_sent = null;
    public $h2_rtt_saved = null;

    public function __construct($remote_address, array $context_option = array())
    {
        parent::__construct($remote_address, $context_option);
    }
}
