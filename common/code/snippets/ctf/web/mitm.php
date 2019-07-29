<?php
    $socket = socket_create(2, 1, 0);
    socket_bind($socket, 0, 3306);
    socket_listen($socket);
 
    $client = socket_accept($socket);
 
    $server = socket_create(2, 1, 0);
    socket_connect($server, '202.112.28.121', 3306);
 
    socket_set_nonblock($client);
    socket_set_nonblock($server);
 
    while(true) {
        $packet = socket_read($server, 4096);
        if($packet) {
            printf("S->C: %s\n", $packet);
            socket_write($client, $packet);
        }
 
        $packet = socket_read($client, 4096);
        if($packet) {
            printf("S<-C: %s\n", $packet);
            socket_write($server, $packet);
        }
        usleep(1e4); 
    }
?>
