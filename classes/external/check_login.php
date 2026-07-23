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

namespace auth_qrcode\external;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->dirroot . '/login/lib.php');

use auth_qrcode\db\model\qrcode;
use auth_qrcode\db\model\qrcode_status;
use coding_exception;
use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_single_structure;
use core_external\external_value;
use moodle_exception;

/**
 * Web Service to check the status of the QR login attempt and log in the user if authorized from another device.
 *
 * @package     auth_qrcode
 * @copyright   2026 MoodleMootDACH
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class check_login extends external_api {
    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function execute_parameters(): external_function_parameters {
        return new external_function_parameters([
            'token' => new external_value(PARAM_ALPHANUM, 'Token'),
            'confirmationcode' => new external_value(PARAM_ALPHANUM, 'Confirmation code', VALUE_DEFAULT),
        ]);
    }

    /**
     * Check the status of the QR login attempt.
     *
     * If this is called from the session trying to log in and the attempt has been authorized on the other device, the session will
     * automatically be logged in.
     *
     * @param string $token
     * @param string|null $confirmationcode
     * @return array
     * @throws coding_exception
     * @throws moodle_exception
     */
    public static function execute(string $token, string|null $confirmationcode): array {
        global $USER;
        $params = self::validate_parameters(
            self::execute_parameters(),
            ['token' => $token, 'confirmationcode' => $confirmationcode]
        );

        $qrcode = qrcode::get_by_token($params['token']);
        if (!$qrcode) {
            return ['status' => 'token_not_found'];
        }

        // Check if session/user has access to this token.
        if (!$qrcode->is_initial_session(session_id()) && intval($USER->id) !== $qrcode->get('userid')) {
            return ['status' => 'token_not_found'];
        }

        if ($qrcode->is_login_authorized()) {
            // The other session authorized this token to login.
            if ($qrcode->check_confirmationcode($params['confirmationcode'])) {
                // Confirmation code is valid or not required, proceed with login.
                $qrcode->perform_login();
            }
        }

        return match ($qrcode->get('status')) {
            qrcode_status::ALLOWED => [
                'status' => 'authorized',
                'remaining_attempts' => $qrcode->get_remaining_attempts(),
                'confirmationcode_length' => qrcode::CONFIRMATIONCODE_LENGTH,
            ],
            qrcode_status::DENIED => [
                'status' => 'not_authorized',
            ],
            qrcode_status::IN_USE, qrcode_status::CREATED => [
                'status' => 'waiting_auth',
            ],
            qrcode_status::LOGGED_IN => [
                'status' => 'logged_in',
                'wantsurl' => core_login_get_return_url(),
            ],
        };
    }

    /**
     * Describe the return structure of the external service.
     *
     * @return external_single_structure
     */
    public static function execute_returns(): external_single_structure {
        return new external_single_structure([
            'status' => new external_value(PARAM_TEXT, 'Status of the login check.'),
            'wantsurl' => new external_value(PARAM_LOCALURL, 'URL to redirect to', VALUE_OPTIONAL),
            'remaining_attempts' => new external_value(PARAM_INT, 'Remaining attempts for confirmation code', VALUE_OPTIONAL),
            'confirmationcode_length' => new external_value(PARAM_INT, 'Length of confirmation code', VALUE_OPTIONAL),
        ]);
    }
}
