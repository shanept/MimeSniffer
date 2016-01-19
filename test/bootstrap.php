<?php
    include __DIR__ . "/autoloader.php";

    $autoloader = new Psr4AutoloaderClass;
    $autoloader->register();

    $dir = dirname(__FILE__);

    $autoloader->addNamespace('Shanept', dirname(__DIR__) . '/src/');
