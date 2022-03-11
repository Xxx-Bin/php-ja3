<?php

class DataShareClinet extends \GlobalData\Client
{


    public function watch($key,$wait =  0)
    {
        $connection = $this->getConnection($key);
        $this->writeToRemote(array(
            'cmd' => 'get',
            'key' => $key,
            'wait' => $wait,
        ), $connection);
        return $this->readFromRemote($connection);
    }

}
