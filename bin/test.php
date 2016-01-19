#!/usr/bin/php
<?php
	define('CWD', dirname(__DIR__));
	chdir(CWD);

	if (!file_exists(CWD . '/vendor/'))
		throw new \RuntimeException('Must run composer install first');

	if (!file_exists(CWD . '/vendor/bin/phpunit'))
		throw new \RuntimeException('Must install developer requirements');

	system(CWD . '/vendor/bin/phpunit');
