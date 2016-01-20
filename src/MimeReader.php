<?php
    namespace Shanept;

    class MimeReader {
        protected $file = null;
        protected $detected_type = null;
        protected $header = null;

        const IGNORE_NOTHING = '';
        const BINARY_CHARACTERS = "\x00\x01\x02\x03\x04\x05\x06\x07\0x08\x0B\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1C\x1D\x1E\x1F";
        const WHITESPACE_CHARACTERS = "\x09\x0A\x0C\x0D\x20";
        const TAG_TERMINATING_CHARACTERS = "\x20\x3E";

        protected static $image = array (
            // Windows Icon
            array (
                'mime'      => 'image/x-icon',
                'pattern'   => "\x00\x00\x01\x00",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // Windows Cursor signature
            array(
                'mime'      => 'image/x-icon',
                'pattern'   => "\x00\x00\x02\x00",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "BM" - BMP signature
            array (
                'mime'      => 'image/bmp',
                'pattern'   => "\x42\x4D",
                'mask'      => "\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "GIF87a" - GIF signature
            array (
                'mime'      => 'image/gif',
                'pattern'   => "\x47\x49\x46\x38\x37\x61",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "GIF89a" - GIF signature
            array (
                'mime'      => 'image/gif',
                'pattern'   => "\x47\x49\x46\x38\x39\x61",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "RIFF" followed by 4 bytes followed by "WEBPVP"
            array (
                'mime'      => 'image/webp',
                'pattern'   => "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x45\x42\x50\x56\x50",
                'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // A byte with only the highest bit set followed by the string "PNG" followed by CR LF SUB LF - PNG signature
            array (
                'mime'      => 'image/png',
                'pattern'   => "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // JPEG start of image marker followed by another marker
            array (
                'mime'      => 'image/jpeg',
                'pattern'   => "\xFF\xD8\xFF",
                'mask'      => "\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "8BPS" - Photoshop signature
            array (
                'mime'      => 'application/psd',
                'pattern'   => "\x38\x42\x50\x53",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
        );

        protected static $media = array (
            // The WebM signature
            array (
                'mime'      => 'video/webm',
                'pattern'   => "\x1A\x45\xDF\xA3",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // The .snd signature
            array (
                'mime'      => 'audio/basic',
                'pattern'   => "\x2E\x73\x6E\x64",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "FORM" followed by 4 bytes followed by "AIFF" - the AIFF signature
            array (
                'mime'      => 'audio/aiff',
                'pattern'   => "\x46\x4F\x52\x4D\x00\x00\x00\x00\x41\x49\x46\x46",
                'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // MP3 without ID3 tag
            array (
                'mime'      => 'audio/mpeg',
                'pattern'   => "\xFF\xFB",
                'mask'      => "\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "ID3" and the ID3v2-tagged MP3 signature
            array (
                'mime'      => 'audio/mpeg',
                'pattern'   => "\x49\x44\x33",
                'mask'      => "\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "OggS" followed by NUL - The OGG signature
            array (
                'mime'      => 'application/ogg',
                'pattern'   => "\x4F\x67\x67\x53\x00",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "MThd" followed by 4 bytes representing the number 6 in 32 bits (big endian) - MIDI signature
            array (
                'mime'      => 'audio/midi',
                'pattern'   => "\x4D\x54\x68\x64\x00\x00\x00\x06",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "RIFF" followed by 4 bytes followed by "AVI" - AVI signature
            array (
                'mime'      => 'video/avi',
                'pattern'   => "\x52\x49\x46\x46\x00\x00\x00\x00\x41\x56\x49\x20",
                'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "RIFF" followed by 4 bytes followed by "WAVE" - WAVE signature
            array (
                'mime'      => 'audio/wave',
                'pattern'   => "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x41\x56\x45",
                'mask'      => "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
        );
        
        protected static $fonts = array (
            // 34 bytes followed by "LP" - Opentype signature
            array (
                'mime'      => 'application/vnd.ms-fontobject',
                'pattern'   => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50",
                'mask'      => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // 4 bytes representing version type 1 of true type font
            array (
                'mime'      => 'application/font-ttf',
                'pattern'   => "\x00\x01\x00\x00",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "OTTO" - Opentype signature
            array (
                'mime'      => 'application/font-off',      // application/vnd.ms-opentype
                'pattern'   => "\x4F\x54\x54\x4F",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "ttcf" - Truetype Collection signature
            array (
                'mime'      => 'application/x-font-truetype-collection',
                'pattern'   => "\x74\x74\x63\x66",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // 'wOFF' - Web Open Font Format signature
            array (
                'mime'      => 'application/font-woff',
                'pattern'   => "\x77\x4F\x46\x46",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
        );

        protected static $archive = array (
            // GZIP signature
            array (
                'mime'      => 'application/x-gzip',
                'pattern'   => "\x1F\x8B\x08",
                'mask'      => "\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "PK" followed by ETX, EOT - ZIP signature
            array (
                'mime'      => 'application/zip',
                'pattern'   => "\x50\x4B\x03\x04",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // "Rar " followed by SUB, BEL, NUL - RAR signature
            array (
                'mime'      => 'application/x-rar-compressed',
                'pattern'   => "\x52\x61\x72\x20\x1A\x07\x00",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
        );
        
        protected static $text = array (
            // "%!PS-Adobe-" - Postscript signature
            array (
                'mime'      => 'application/postscript',
                'pattern'   => "\x25\x21\x50\x53\x2D\x41\x64\x6F\x62\x65",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // UTF-16 Big Endian BOM text
            array (
                'mime'      => 'text/plain',
                'pattern'   => "\xFF\xFE",
                'mask'      => "\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // UTF-16 Little Endian BOM text
            array (
                'mime'      => 'text/plain',
                'pattern'   => "\xFE\xFF",
                'mask'      => "\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            // UTF-8 BOM text
            array (
                'mime'      => 'text/plain',
                'pattern'   => "\xEF\xBB\xBF",
                'mask'      => "\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
        );
        
        protected static $others = array (
            array (
                'mime'      => 'WINDOWS EXECUTABLE',
                'pattern'   => "\x4D\x5A",
                'mask'      => "\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            ),
            array (
                'mime'      => 'EXEC_LINKABLE',
                'pattern'   => "\x7F\x45\x4C\x46",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
        );

        protected static $unknown = array (
            // "<!DOCTYPE HTML"
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x21\x44\x4F\x43\x54\x59\x50\x45\x20\x48\x54\x4D\x4C",
                'mask'      => "\xFF\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xFF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<HTML" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x48\x54\x4D\x4C",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<HEAD" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x48\x45\x41\x44",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<SCRIPT" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x53\x43\x52\x49\x50\x54",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<IFRAME" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x49\x46\x52\x41\x4D\x45",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<H1" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x48\x31",
                'mask'      => "\xFF\xDF\xFF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<DIV" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x44\x49\x56",
                'mask'      => "\xFF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<FONT" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x46\x4F\x4E\x54",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<TABLE" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x54\x41\x42\x4C\x45",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<A" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x41",
                'mask'      => "\xFF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<STYLE" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x53\x54\x59\x4C\x45",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<TITLE" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x54\x49\x54\x4C\x45",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<B" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x42",
                'mask'      => "\xFF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<BODY" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x42\x4F\x44\x59",
                'mask'      => "\xFF\xDF\xDF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<BR" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x42\x52",
                'mask'      => "\xFF\xDF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<P"
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x50",
                'mask'      => "\xFF\xDF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // "<!--" followed by a tag-terminating byte
            array (
                'mime'      => 'text/html',
                'pattern'   => "\x3C\x21\x2D\x2D",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS,
                'trailing'  => self::TAG_TERMINATING_CHARACTERS
            ),
            // The string "<?xml"
            array (
                'mime'      => 'text/xml',
                'pattern'   => "\x3C\x3F\x78\x6D\x6C",
                'mask'      => "\xFF\xFF\xFF\xFF\xFF",
                'ignore'    => self::WHITESPACE_CHARACTERS
            ),
            // "%PDF" - PDF signature
            array (
                'mime'      => 'application/pdf',
                'pattern'   => "\x25\x50\x44\x46",
                'mask'      => "\xFF\xFF\xFF\xFF",
                'ignore'    => self::IGNORE_NOTHING
            )
            // "PK" followed by 18 bytes - Microsoft Open Office signature
/*          array (
                'mime'      => 'application/docx',
                'pattern'   => "\x50\x4B\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                'mask'      => "\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                'ignore'    => self::IGNORE_NOTHING
            ) */
        );

        public function __construct($file) {
            $this->file = $file;

            $this->readResourceHeader();
            $this->detectType();
        }

        /* The public API */
        public function isEmpty() {
            if ('inode/x-empty' === $this->detected_type)
                return true;

            return false;
        }

        public function isText() {
            $detected = false;

            switch ($this->detected_type) {
                case 'application/postscript':
                case 'text/plain':
                    $detected = true;
                    break;
                default:
                    break;
            }

            return $detected;
        }

        public function isFont() {
            $detected = false;

            switch ($this->detected_type) {
                case 'application/font-ttf':
                case 'application/font-cff':
                case 'application/font-otf':
                case 'application/font-sntf':
                case 'application/vds.ms-opentype':
                case 'application/font-woff':
                case 'application/vnd.ms-fontobject':
                    $detected = true;
                    break;
                default:
                    break;
            }

            return $detected;
        }

        public function isZip() {
            $detected = false;

            switch ($this->detected_type) {
                case 'application/zip':
                    $detected = true;
                    break;
                default:
                    break;
            }

            if (substr($this->detected_type, -4) === '+zip')
                $detected = true;

            return $detected;
        }

        public function isArchive() {
            $detected = false;

            switch ($this->detected_type) {
                case 'application/x-rar-compressed':
                case 'application/zip':
                case 'application/x-gzip':
                    $detected = true;
                    break;
                default:
                    break;
            }

            return $detected;
        }

        public function isScriptable() {
            $detected = false;

            switch ($this->detected_type) {
                case 'text/html':
                case 'application/pdf':
                case 'application/postscript':
                    $detected = true;
                    break;
                default:
                    break;
            }

            return $detected;
        }

        public function getType() {
            return $this->detected_type;
        }

        /**
         * Helper functions.
         *  Execution is passed over to detectType after the
         *  construct sets up the data.
         */
        protected function readResourceHeader() {
            if (is_string($this->file)) {
                $fp     = fopen($this->file, 'r');
                $header = fread($fp, 512);
                fclose($fp);
            } else {
                // The current position may not be at the start. Let's take it then set to
                //  start of file, read 512 bytes then reset to last position.
                $position   = ftell($this->file);
                fseek($this->file, 0, SEEK_SET);
                $header     = fread($this->file, 512);
                fseek($this->file, $position, SEEK_SET);
            }

            $this->header = &$header;
        }

        protected function matchPattern($pattern, $mask, $ignore) {
            if (empty($pattern) || empty($mask)) {
                return false;
            }
            $s = 0;

            $sequence       = &$this->header;
            $seq_len        = strlen($sequence);
            $pattern_len    = strlen($pattern);
            $mask_len       = strlen($mask);

            if ($pattern_len !== $mask_len) {
                return false;
            }

            // First we will set $s so that it ignores the first bytes if it needs to
            if (!empty($ignore)) {
                for ($s = 0; $s < $seq_len;) {
                    // This letter should not be ignored.
                    if (strpos($ignore, $sequence{$s}) === false) {
                        break;
                    }

                    ++$s;
                }
            }

            // Our sequence is not long enough to fit our pattern and/or trailing bits
            if (($seq_len - $s) < $mask_len) {
                return false;
            }

            // Now we will compare. If it doesn't match the mask, we return false.
            for ($i = 0; $i < $pattern_len;) {
                $masked_data    = $sequence{$s} & $mask{$i};

                if ($masked_data !== $pattern{$i}) {
                    return false;
                }

                ++$i; ++$s;
            }

            // Mask matched. This pattern matches.
            return true;
        }

        protected function htmlMatchPattern($pattern, $mask, $ignore, $trailing) {
            if (empty($pattern) || empty($mask)) {
                return false;
            }
            $s  = 0; $i = 0;

            $sequence       = &$this->header;
            $seq_len        = strlen($sequence);
            $pattern_len    = strlen($pattern);
            $mask_len       = strlen($mask);

            if ($pattern_len !== $mask_len) {
                if (empty($trailing))
                    return false;
            }

            // First we will set $s so that it ignores the first bytes if it needs to
            if (!empty($ignore)) {
                for (; $s < $seq_len;) {
                    // This letter should not be ignored.
                    if (strpos($ignore, $sequence{$s}) === false) {
                        break;
                    }

                    ++$s;
                }
            }

            // Our sequence is not long enough to fit our pattern and/or trailing bits
            if (($seq_len - $s) < $mask_len) {
                return false;
            }

            // Now we will compare. If it doesn't match the mask, we return false.
            for (; $i < $pattern_len; $i++, $s++) {
                $masked_data = $sequence{$s} & $mask{$i};

                if ($masked_data !== $pattern{$i}) {
                    return false;
                }
            }

            // Mask matched. Let us check for trailing bytes.
            for (; $i < $mask_len; $i++, $s++) {
                $masked_data = $sequence{$s} & $mask{$i};

                if (false === strpos($trailing, $masked_data))
                    return false;
            }

            return true;
        }

        protected function detectType() {
            if ($this->sniffEmpty())    return;
            if ($this->sniffImages())   return;
            if ($this->sniffMedia())    return;
            if ($this->sniffFonts())    return;
            if ($this->sniffArchive())  return;
            if ($this->sniffText())     return;
            if ($this->sniffUnknown())  return;
            if ($this->sniffOthers())   return;
        }

        /* Sniffer functions */
        protected function sniffEmpty() {
            if (strlen($this->header) === 0) {
                $this->detected_type    = 'inode/x-empty';
                return true;
            }

            return false;
        }

        protected function sniffImages() {
            $num_imgs = count(self::$image);

            for ($i = 0; $i < $num_imgs; $i++) {
                $im = &self::$image[$i];

                if ($this->matchPattern($im['pattern'], $im['mask'], $im['ignore'])) {
                    $this->detected_type = $im['mime'];
                    return true;
                }
            }

            return false;
        }

        protected function sniffMedia() {
            $num_media = count(self::$media);

            for ($i = 0; $i < $num_media; $i++) {
                $m = &self::$media[$i];
                if ($this->matchPattern($m['pattern'], $m['mask'], $m['ignore'])) {
                    $this->detected_type = $m['mime'];
                    return true;
                }
            }

            if ($this->sniffMp4()) {
                $this->detected_type = 'video/mp4';
                return true;
            }

            return false;
        }

        protected function sniffMp4() {
            $sequence   = &$this->header;
            $seq_len    = strlen($sequence);

            if ($seq_len < 12) {
                return false;
            }

            $box_size = substr($sequence, 0, 4);
            $box_size = unpack('N', $box_size);
            $box_size = $box_size[1];

            if ($seq_len < $box_size)
                return false;

            if ($box_size % 4)
                return false;


            if (substr($sequence, 4, 4) !== "\x66\x74\x79\x70")
                return false;

            if (substr($sequence, 8, 3) === "\x6D\x70\x34")
                return true;

            $i = 16;
            while ($i < $box_size) {
                if (substr($sequence, $i, 3) === "\x6D\x70\x34")
                    return true;

                $i += 4;
            }

            return false;
        }

        protected function sniffFonts() {
            $num_fonts = count(self::$fonts);

            for ($i = 0; $i < $num_fonts; $i++) {
                $f = &self::$fonts[$i];
                if ($this->matchPattern($f['pattern'], $f['mask'], $f['ignore'])) {
                    $this->detected_type = $f['mime'];
                    return true;
                }
            }

            return false;
        }

        protected function sniffArchive() {
            $num_archives = count(self::$archive);

            for ($i = 0; $i < $num_archives; $i++) {
                $a = &self::$archive[$i];
                if ($this->matchPattern($a['pattern'], $a['mask'], $a['ignore'])) {
                    $this->detected_type = $a['mime'];
                    return true;
                }
            }

            return false;
        }

        protected function sniffText() {
            $num_texts = count(self::$text);

            for ($i = 0; $i < $num_texts; $i++) {
                $t = &self::$text[$i];
                if ($this->matchPattern($t['pattern'], $t['mask'], $t['ignore'])) {
                    if ($this->has_binary_data()) {
                        return false;
                    } else {
                        $this->detected_type = $t['mime'];
                        return true;
                    }
                }
            }

            return false;
        }

        protected function sniffUnknown() {
            $num_unknown = count(self::$unknown);
            for ($i = 0; $i < $num_unknown; $i++) {
                $u = &self::$unknown[$i];
                if ('text/html' === $u['mime']) {
                    $trailing = (array_key_exists('trailing', $u) ? $u['trailing'] : '');
                    if ($this->htmlMatchPattern($u['pattern'], $u['mask'], $u['ignore'], $trailing)) {
                        $this->detected_type = 'text/html';
                        return true;
                    }
                } else {
                    if ($this->matchPattern($u['pattern'], $u['mask'], $u['ignore'])) {
                        $this->detected_type = $u['mime'];
                        return true;
                    }
                }
            }

            return false;
        }

        protected function sniffOthers() {
            $num_others = count(self::$others);
            for ($i = 0; $i < $num_others; $i++) {
                $o = &self::$others[$i];
                if ($this->matchPattern($o['pattern'], $o['mask'], $o['ignore'])) {
                    $this->detected_type = $o['mime'];
                    return true;
                }
            }

            return false;
        }

        protected function hasBinaryData() {
            static $binary_chars;

            if (is_string($binary_chars))
                $binary_chars = str_split($this->binary_characters);

            $num_chars = count($binary_chars);
            for ($i = 0; $i < $num_chars; $i++) {
                if (strpos($this->header, $binary_chars[$i]) !== false) {
                    return true;
                }
            }

            return false;
        }
    }
