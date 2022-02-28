# php-ja3
php for SSL/TLS ja3 fingerprint.


## Installing
composer install

## Data transfer direction
> brower => php-ja3(INBOUND) => catch JA3 => php-ja3(OUTBOUND) => nginx(https=>http) => /web/ja3.php

## Config
### wkm_ja3.php
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

### Tests
#### request
```
curl https://example.com:9763/ja3.php
```

#### return
>{"ja3t_hash":"","ja3_hash":"cd08e314……c695473da9","ja3s_hash":"d7e12962b……f39221f9e8"}

##  catch all requst 
```php
// public ip 
define('INBOUND','tcp://example.com:443'); 
// private ip (nginx need to listen it too)
define('OUTBOUND','tcp://127.0.0.1:443');
```






##  demo 
[php-JA3er TLS握手指纹实践](https://bjun.tech/blog/xphp/141#demo_38)



##  relevant 
[ja3](https://github.com/salesforce/ja3)

[workerman](https://github.com/walkor/workerman)
