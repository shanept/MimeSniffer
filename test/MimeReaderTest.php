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
    }
