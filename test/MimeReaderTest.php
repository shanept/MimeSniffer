<?php

    use Shanept\MimeReader;

    class MimeReaderTest extends PHPUnit_Framework_TestCase {
        private $old_dir;
        private $gen_dir;

        private static $magic_files = array (
            // images
            'windows-icon.ico'      => "\x00\x00\x01\x00",
            'windows-cursor.cur'    => "\x00\x00\x02\x00",
            'bitmap-image.bmp'      => "\x42\x4D",
            'gif-87a-image.gif'     => "\x47\x49\x46\x38\x37\x61",
            'gif-89a-image.gif'     => "\x47\x49\x46\x38\x39\x61",
            'webp-image.webp'       => "RIFF\x00\x00\x00\x00WEBPVP",
            'png-image.png'         => "\x89PNG\x0D\x0A\x1A\x0A",
            'jpeg-image.jpg'        => "\xFF\xD8\xFF",
            'photoshop-image.psd'   => "8BPS",

            // media
            'webm-video.webm'       => "\x1A\x45\xDF\xA3",
            'basic-audio.au'        => '.snd',
            'aiff-audio.aiff'       => "FORM\x00\x00\x00\x00AIFF",
            'mp3-audio.mp3'         => "\xFF\xFB",
            'mp3-ID3-audio.mp3'     => "\x49\x44\x33",
            'ogg-vorbis-audio.ogg'  => "OggS\x00",
            'midi-audio.midi'       => "MThd\x00\x00\x00\x06",
            'avi-video.avi'         => "RIFF\x00\x00\x00\x00AVI\x20",
            'wave-audio.wave'       => "RIFF\x00\x00\x00\x00WAVE",

            // fonts
            'opentype1-font.otf'    => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
            'truetype-font.ttf'     => "\x00\x01\x00\x00",
            'opentype2-font.otf'    => 'OTTO',
            'ttf-collection.ttc'    => 'ttcf',
            'woff-font.woff'        => 'wOFF',

            // archive
            'gzip-archive.gz'       => "\x1F\x8B\x08",
            'zip-archive.zip'       => "PK\x03\x04",
            'rar-archive.rar'       => "Rar \x1A\x07\x00",

            // text
            'postscript.ps'         => "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65",
            'utf16-big-endian.txt'  => "\xFF\xFE",
          'utf16-little-endian.txt' => "\xFE\xFF",
            'utf8-bom.txt'          => "\xEF\xBB\xBF",

            // others
            'windows-exe.exe'       => "\x4D\x5A",
            'elf-exe.elf'           => "\x7FELF",
            'pdf-file.pdf'          => '%PDF',

            // html
            'doctype-tag.html'      => '<!DOCTYPE html>',
            'html-tag.html'         => '<html>',
            'head-tag.html'         => '<head>',
            'script-tag.html'       => '<script>',
            'iframe-tag.html'       => '<iframe>',
            'h1-tag.html'           => '<h1>',
            'div-tag.html'          => '<div>',
            'font-tag.html'         => '<font>',
            'table-tag.html'        => '<table>',
            'a-tag.html'            => '<a>',
            'style-tag.html'        => '<style>',
            'title-tag.html'        => '<title>',
            'b-tag.html'            => '<b>',
            'body-tag.html'         => '<body>',
            'br-tag.html'           => '<br>',
            'p-tag.html'            => '<p>',
            'comment-tag.html'      => '<!-- ',
            'xml-tag.html'          => '<?xml',

        );

        public function setUp()
        {
            $this->gen_dir = __DIR__ . '/generated/';
            $this->old_dir = getcwd();

            if (!file_exists($this->gen_dir))
                mkdir($this->gen_dir);

            chdir($this->gen_dir);

            foreach (self::$magic_files as $file=>$contents) {
                $fp = fopen($file, 'wb');
                fwrite($fp, $contents);
                fclose($fp);
            }
        }

        public function tearDown()
        {
            foreach (self::$magic_files as $file=>$contents) {
                if (file_exists($file)) {
                    unlink($file);
                }
            }

            chdir($this->old_dir);
            rmdir($this->gen_dir);
        }

        public function testWindowsIcon()
        {
            $mime = new MimeReader('windows-icon.ico');

            $this->assertEquals('image/x-icon', $mime->getType());
        }

        public function testWindowsCursor()
        {
            $mime = new MimeReader('windows-cursor.cur');

            $this->assertEquals('image/x-icon', $mime->getType());
        }

        public function testBMP()
        {
            $mime = new MimeReader('bitmap-image.bmp');

            $this->assertEquals('image/bmp', $mime->getType());
        }

        public function testGIF87a()
        {
            $mime = new MimeReader('gif-87a-image.gif');

            $this->assertEquals('image/gif', $mime->getType());
        }

        public function testGIF89a()
        {
            $mime = new MimeReader('gif-89a-image.gif');

            $this->assertEquals('image/gif', $mime->getType());
        }

        public function testWEBP()
        {
            $mime = new MimeReader('webp-image.webp');

            $this->assertEquals('image/webp', $mime->getType());
        }

        public function testPNG()
        {
            $mime = new MimeReader('png-image.png');

            $this->assertEquals('image/png', $mime->getType());
        }

        public function testJPG()
        {
            $mime = new MimeReader('jpeg-image.jpg');

            $this->assertEquals('image/jpeg', $mime->getType());
        }

        public function testPSD()
        {
            $mime = new MimeReader('photoshop-image.psd');

            $this->assertEquals('application/psd', $mime->getType());
        }

        public function testWEBM()
        {
            $mime = new MimeReader('webm-video.webm');

            $this->assertEquals('video/webm', $mime->getType());
        }

        public function testBasicAudio()
        {
            $mime = new MimeReader('basic-audio.au');

            $this->assertEquals('audio/basic', $mime->getType());
        }

        public function testAIFF()
        {
            $mime = new MimeReader('aiff-audio.aiff');

            $this->assertEquals('audio/aiff', $mime->getType());
        }

        public function testMP3Taggless()
        {
            $mime = new MimeReader('mp3-audio.mp3');

            $this->assertEquals('audio/mpeg', $mime->getType());
        }

        public function testMP3Tagged()
        {
            $mime = new MimeReader('mp3-ID3-audio.mp3');

            $this->assertEquals('audio/mpeg', $mime->getType());
        }

        public function testOGG()
        {
            $mime = new MimeReader('ogg-vorbis-audio.ogg');

            $this->assertEquals('application/ogg', $mime->getType());
        }

        public function testMIDI()
        {
            $mime = new MimeReader('midi-audio.midi');

            $this->assertEquals('audio/midi', $mime->getType());
        }

        public function testAVI()
        {
            $mime = new MimeReader('avi-video.avi');

            $this->assertEquals('video/avi', $mime->getType());
        }

        public function testWAVE()
        {
            $mime = new MimeReader('wave-audio.wave');

            $this->assertEquals('audio/wave', $mime->getType());
        }

        public function testTTF()
        {
            $mime = new MimeReader('truetype-font.ttf');

            $this->assertEquals('application/font-ttf', $mime->getType());
        }

        public function testOTF1()
        {
            $mime = new MimeReader('opentype1-font.otf');

            $this->assertEquals('application/vnd.ms-fontobject', $mime->getType());
        }

        public function testOTF2()
        {
            $mime = new MimeReader('opentype2-font.otf');

            $this->assertEquals('application/font-off', $mime->getType());
        }

        public function testTTFCollection()
        {
            $mime = new MimeReader('ttf-collection.ttc');

            $this->assertEquals('application/x-font-truetype-collection', $mime->getType());
        }

        public function testWOFF()
        {
            $mime = new MimeReader('woff-font.woff');

            $this->assertEquals('application/font-woff', $mime->getType());
        }

        public function testGZIP()
        {
            $mime = new MimeReader('gzip-archive.gz');

            $this->assertEquals('application/x-gzip', $mime->getType());
        }

        public function testZIP()
        {
            $mime = new MimeReader('zip-archive.zip');

            $this->assertEquals('application/zip', $mime->getType());
        }

        public function testRAR()
        {
            $mime = new MimeReader('rar-archive.rar');

            $this->assertEquals('application/x-rar-compressed', $mime->getType());
        }

        public function testPostScript()
        {
            $mime = new MimeReader('postscript.ps');

            $this->assertEquals('application/postscript', $mime->getType());
        }

        public function testUTF16Big()
        {
            $mime = new MimeReader('utf16-big-endian.txt');

            $this->assertEquals('text/plain', $mime->getType());
        }

        public function testUTF16Little()
        {
            $mime = new MimeReader('utf16-little-endian.txt');

            $this->assertEquals('text/plain', $mime->getType());
        }

        public function testUTF8BOM()
        {
            $mime = new MimeReader('utf8-bom.txt');

            $this->assertEquals('text/plain', $mime->getType());
        }

        public function testWinEXE()
        {
            $mime = new MimeReader('windows-exe.exe');

            $this->assertEquals('application/x-msdownload', $mime->getType());
        }

        public function testELF()
        {
            $mime = new MimeReader('elf-exe.elf');

            $this->assertEquals('application/octet-stream', $mime->getType());
        }

        public function testPDF()
        {
            $mime = new MimeReader('pdf-file.pdf');

            $this->assertEquals('application/pdf', $mime->getType());
        }

        public function testDOCTYPE()
        {
            $mime = new MimeReader('doctype-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testHTML()
        {
            $mime = new MimeReader('html-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testHEAD()
        {
            $mime = new MimeReader('head-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testSCRIPT()
        {
            $mime = new MimeReader('script-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testIFRAME()
        {
            $mime = new MimeReader('iframe-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testH1()
        {
            $mime = new MimeReader('h1-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testDIV()
        {
            $mime = new MimeReader('div-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testFONT()
        {
            $mime = new MimeReader('font-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testTABLE()
        {
            $mime = new MimeReader('table-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testA()
        {
            $mime = new MimeReader('a-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testSTYLE()
        {
            $mime = new MimeReader('style-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testTITLE()
        {
            $mime = new MimeReader('title-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testB()
        {
            $mime = new MimeReader('b-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testBODY()
        {
            $mime = new MimeReader('body-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testBR()
        {
            $mime = new MimeReader('br-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testP()
        {
            $mime = new MimeReader('p-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testCOMMENT()
        {
            $mime = new MimeReader('comment-tag.html');

            $this->assertEquals('text/html', $mime->getType());
        }

        public function testXML()
        {
            $mime = new MimeReader('xml-tag.html');

            $this->assertEquals('text/xml', $mime->getType());
        }
    }
