<?php

    // Ensure we operate out of the test directory
    chdir(__DIR__);
	require_once '../src/MimeReader.php';

    $html_file = tempnam(sys_get_temp_dir(), 'MimeReader-');
    $file = fopen($html_file, 'w+');
    fwrite($file, '<!doctype html>');
    fclose($file);

	$files	= array (
		'./image.jpg', './image.png', './image.gif',
		'./image.bmp', './Test.pdf', './empty.txt',
        $html_file
	);

	echo '<table>';

	foreach ( $files as $file ) {
		$fp		= fopen( $file, 'r' );
		$buffer	= fread( $fp, 16 );
		fclose( $fp );

		echo '<tr><td>' . $file . '</td><td>';

		$type	= '<b>UNKNOWN</b>';

		$reader	= new MimeReader($file);

		echo $reader->get_type() . '</td></tr>';
	}

	echo '</table>';
