<?php
	include( '../mimereader.class.php' );

	$files	= array (
		'./image.jpg', './image.png', './image.gif',
		'./image.bmp', './Test.pdf'
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
