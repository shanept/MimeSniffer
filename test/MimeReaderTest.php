<?php

use Shanept\MimeReader;
use org\bovigo\vfs\vfsStream;

class MimeReaderTest extends PHPUnit_Framework_TestCase
{
    public function dataSet()
    {
        return array(
            // images
            array('/windows-icon.ico', "\x00\x00\x01\x00", 'image/x-icon'),
            array('/windows-cursor.cur', "\x00\x00\x02\x00", 'image/x-icon'),
            array('/bitmap-image.bmp', "\x42\x4D", 'image/bmp'),
            array('/gif-87a-image.gif', "\x47\x49\x46\x38\x37\x61", 'image/gif'),
            array('/gif-89a-image.gif', "\x47\x49\x46\x38\x39\x61", 'image/gif'),
            array('/webp-image.webp', "RIFF\x00\x00\x00\x00WEBPVP", 'image/webp'),
            array('/png-image.png', "\x89PNG\x0D\x0A\x1A\x0A", 'image/png'),
            array('/jpeg-image.jpg', "\xFF\xD8\xFF", 'image/jpeg'),
            array('/photoshop-image.psd', '8BPS', 'application/psd'),

            // media
            array('/webm-video.webm', "\x1A\x45\xDF\xA3", 'video/webm'),
            array('/basic-audio.au', '.snd', 'audio/basic'),
            array('/aiff-audio.aiff', "FORM\x00\x00\x00\x00AIFF", 'audio/aiff'),
            array('/mp3-audio.mp3', "\xFF\xFB", 'audio/mpeg'),
            array('/mp3-ID3-audio.mp3', "\x49\x44\x33", 'audio/mpeg'),
            array('/ogg-vorbis-audio.ogg', "OggS\x00", 'application/ogg'),
            array('/midi-audio.midi', "MThd\x00\x00\x00\x06", 'audio/midi'),
            array('/avi-video.avi', "RIFF\x00\x00\x00\x00AVI\x20", 'video/avi'),
            array('/wave-audio.wave', "RIFF\x00\x00\x00\x00WAVE", 'audio/wave'),

            // fonts
            array('/truetype-font.ttf', "\x00\x01\x00\x00", 'application/font-ttf'),
            array('/opentype1-font.otf', str_repeat("\x00", 34) . 'LP', 'application/vnd.ms-fontobject'),
            array('/opentype2-font.otf', 'OTTO', 'application/font-off'),
            array('/ttf-collection.ttc', 'ttcf', 'application/x-font-truetype-collection'),
            array('/woff-font.woff', 'wOFF', 'application/font-woff'),

            // archive
            array('/gzip-archive.gz', "\x1F\x8B\x08", 'application/x-gzip'),
            array('/zip-archive.zip', "PK\x03\x04", 'application/zip'),
            array('/rar-archive.rar', "Rar \x1A\x07\x00", 'application/x-rar-compressed'),

            // text
            array('/postscript.ps', "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65", 'application/postscript'),
            array('/utf16-big-endian.txt', "\xFF\xFE", 'text/plain'),
            array('/utf16-little-endian.txt', "\xFE\xFF", 'text/plain'),
            array('/utf8-bom.txt', "\xEF\xBB\xBF", 'text/plain'),

            // others
            array('/windows-exe.exe', "\x4D\x5A", 'application/x-msdownload'),
            array('/elf-exe.elf', "\x7FELF", 'application/octet-stream'),
            array('/pdf-file.pdf', '%PDF', 'application/pdf'),

            // html
            array('/doctype-tag.html', '<!DOCTYPE html>', 'text/html'),
            array('/html-tag.html', '<html>', 'text/html'),
            array('/head-tag.html', '<head>', 'text/html'),
            array('/script-tag.html', '<script>', 'text/html'),
            array('/iframe-tag.html', '<iframe>', 'text/html'),
            array('/h1-tag.html', '<h1>', 'text/html'),
            array('/div-tag.html', '<div>', 'text/html'),
            array('/font-tag.html', '<font>', 'text/html'),
            array('/table-tag.html', '<table>', 'text/html'),
            array('/a-tag.html', '<a>', 'text/html'),
            array('/style-tag.html', '<style>', 'text/html'),
            array('/title-tag.html', '<title>', 'text/html'),
            array('/b-tag.html', '<b>', 'text/html'),
            array('/body-tag.html', '<body>', 'text/html'),
            array('/br-tag.html', '<br>', 'text/html'),
            array('/p-tag.html', '<p>', 'text/html'),
            array('/comment-tag.html', '<!-- ', 'text/html'),
            array('/xml-tag.html', '<?xml', 'text/xml'),

            // Final unknown file type.
            array('/unknown.sniffme', "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", 'application/octet-stream'),
        );
    }

    /**
     * @param $filename The filename to inspect
     * @param $content  The content of the file
     * @param $type     The type to be asserted against
     *
     * @dataProvider dataSet
     */
    public function testMimeSniffer($filename, $content, $type)
    {
        $vfs  = vfsStream::setup();
        $file = vfsStream::url($vfs->getName() . $filename);

        $fp = fopen($file, 'wb');
        fwrite($fp, $content);
        fclose($fp);

        $reader = new MimeReader($file);
        $this->assertSame($type, $reader->getType());
    }
}
