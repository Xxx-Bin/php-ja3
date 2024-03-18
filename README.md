# php-ja3
php for SSL/TLS ja3 fingerprint.
This project has three ideas, one is to cooperate with the web server ([wkm_ja3.php](#wkm_ja3php)) and its improved version([wkm_ja3_ex.php](#wkm_ja3_exphp)) , and the other is to monitor the tcpdump standard output ([ja3_tcpdump.php](#ja3_tcpdumpphp))



## Installing
composer install

## wkm_ja3_ex.php
### Data transfer direction
>brower => php-ja3-ex(INBOUND) => catch JA3 => php-ja3-ex(OUTBOUND) => php-ja3-ex(https server)  

### Config
#### Change TcpConnection.php
```php

// ./vendor/workerman/workerman/Connection/TcpConnection.php line 745


		if(defined('STREAM_CRYPTO_METHOD_SERVER')){
                         $type = \STREAM_CRYPTO_METHOD_SERVER;
                }else{
                        $type = \STREAM_CRYPTO_METHOD_SSLv2_SERVER | \STREAM_CRYPTO_METHOD_SSLv23_SERVER;
                }


```

#### INBOUND

```php
// one prot 9764
define('INBOUND','tcp://0.0.0.0:9764');

```
#### OUTBOUND 

```php
//Also Https service
define('OUTBOUND','tcp://127.0.0.1:9765');
```

### Run
```
php wkm_ja3_ex.php start -d
```
### Tests
#### request
```
curl https://example.com:9764/
```

### demo
[php-ja3-ex demo](https://bjun.tech/blog/xphp/218#demo_18)

## ja3_tcpdump.php
### Data transfer direction
```
brower =>  nginx(https=>http) => /web/ja3.php
            | |                     A
             V                     | |
           tcpdump => stdout =>  ja3_tcpdump.php
```

### Config
#### TCPDUMP_LISTEN_INTERFACE
```php
// tcpdump listen interface, defautl 1. See 'tcpdump - D' for details
define('TCPDUMP_LISTEN_INTERFACE',1);
```

### Run
```bash
sudo  php ja3_tcpdump.php start -d
```

### Tests
#### request
```
curl https://example.com/ja3.php
```

#### return
>{"ja3_hash":"0d69ff4……2834766","speed_time":0.402}

### demo and blog
[php、ja3和tcpdump (TLS握手指纹实践2)](https://bjun.tech/blog/xphp/144#demo_48)

### Some problems
1. return none
    If you visit after a period of time, you will return none. You need to go to the following link to close the socket before the TLS handshake can occur again
    [chrome://net-internals/#sockets](chrome://net-internals/#sockets)
2. so slow
    With curl request, the average time spent is 0.5 minutes 02 ~ 0.6s, mainly due to the slow return of the command Popen ('tcpdump.. '). I don't know how to optimize it
    

## ja3_tshark.php
The operation is  same to  ja3_tcpdump. The only thing to note is that the tshark version requires 3.*

## wkm_ja3.php
### Data transfer direction
> brower => php-ja3(INBOUND) => catch JA3 => php-ja3(OUTBOUND) => nginx(https=>http) => /web/ja3.php

### Config
#### INBOUND

```php
// one prot 9763
define('INBOUND','tcp://0.0.0.0:9763');

```
#### OUTBOUND
```php
define('OUTBOUND','tcp://example.com:443');
```

### nginx 
```ngixn
server {
    listen :443 ssl ;
    server_name example.com;
    …… ssl set
    root "pathto/php-ja3/web";
    location ~ \.php(.*)$ {
    ……  
    }
```

### Run
```
php wkm_ja3.php start -d
``` 


### Tests
#### request
```
curl https://example.com:9763/ja3.php
```

#### return
>{"ja3_hash":"0d69ff4……2834766","speed_time":0.402}

###  catch all request 
```php
// public ip 
define('INBOUND','tcp://example.com:443'); 
// private ip (nginx need to listen it too)
define('OUTBOUND','tcp://127.0.0.1:443');
```





###  demo 
[php-JA3er TLS握手指纹实践](https://bjun.tech/blog/xphp/141#demo_38)

## update

2024-03-18 add JA4，about JA4 see[JA4 初探](https://bjun.tech/blog/xphp/246)

##  relevant 
[ja3](https://github.com/salesforce/ja3)

[workerman](https://github.com/walkor/workerman)
