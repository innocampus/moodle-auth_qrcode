<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * qrcode generator.
 *
 * @package   auth_qrcode
 * @author    Sascha Vogel (sascha.vogel@ffhs.ch)
 * @copyright 2026 MoodleMootDACH
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_qrcode;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/tcpdf/tcpdf_barcodes_2d.php');

/**
 * qrcode generator class.
 */
class qrcode_generator {
    /**
     * generate qrcode.
     *
     * @param string $uri
     * @return string
     */
    public static function generate_qrcode(string $uri = ''): string {
        $qrcode = new  \TCPDF2DBarcode($uri, 'QRCODE');
        $image = $qrcode->getBarcodeSVGcode(20, 20);
        $html = \html_writer::img('data:image/svg+xml;base64,' . base64_encode($image), '', ['width' => '70%']);
        return $html;
    }
}
