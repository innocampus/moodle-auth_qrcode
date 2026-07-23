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
 * Display the confirmation page after a user has scanned a QR-Code.
 *
 * @package    auth_qrcode
 * @copyright  2026 MoodleMootDACH
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 *
 * {@noinspection PhpUnhandledExceptionInspection}
 */

use auth_qrcode\db\model\qrcode;
use auth_qrcode\db\model\qrcode_status;

require_once(__DIR__ . '/../../config.php');

global $PAGE, $OUTPUT, $USER, $SITE;

$token = required_param('token', PARAM_ALPHANUM);

$context = context_system::instance();
$PAGE->set_context($context);

$PAGE->set_url('/auth/qrcode/confirm.php', ['token' => $token]);
$PAGE->set_pagelayout('standard');
$PAGE->set_title(get_string('login_via_qrcode', 'auth_qrcode'));
$PAGE->set_heading(get_string('login_via_qrcode', 'auth_qrcode'));

if (!is_enabled_auth('qrcode')) {
    throw new moodle_exception('pluginisdisabled', 'auth_qrcode');
}

require_login(autologinguest: false);

echo $OUTPUT->header();

// Check if the token is valid.
$qrcode = qrcode::get_by_token($token);
if (!$qrcode) {
    echo $OUTPUT->notification(get_string('invalid_token_or_expired', 'auth_qrcode'), 'danger', false);
    echo $OUTPUT->footer();
    exit;
}

// Check if user is allowed to log in with their primary method.
if ($USER->auth == 'nologin' || !is_enabled_auth($USER->auth)) {
    // Suspended accounts will lose their session, no need to check for this explicitly.
    echo $OUTPUT->notification(get_string('login_rejected', 'auth_qrcode'), 'error', false);
    echo $OUTPUT->footer();
    exit;
}

// Check if the token should be denied.
if (optional_param('deny', false, PARAM_BOOL)) {
    require_sesskey();
    $success = $qrcode->deny();
    if ($success || $qrcode->get('status') === qrcode_status::DENIED) {
        echo $OUTPUT->notification(get_string('login_denied', 'auth_qrcode'), 'info', false);
    } else {
        echo $OUTPUT->notification(get_string('expired_or_rejected', 'auth_qrcode'), 'error', false);
    }
    echo $OUTPUT->footer();
    exit;
}

// Check if the token should be allowed.
if (optional_param('allow', false, PARAM_BOOL)) {
    require_sesskey();
    $success = $qrcode->allow($USER->id);
    if ($success) {
        $confirmationcode = $qrcode->get('confirmationcode');
        if ($confirmationcode) {
            // Render page with confirmation code.
            $PAGE->requires->js_call_amd('auth_qrcode/confirm', 'init', [$token]);
            $context = [
                'confirmationcode' => $confirmationcode,
                'sesskey' => sesskey(),
            ];
            echo $OUTPUT->render_from_template('auth_qrcode/confirmationcode', $context);
        } else {
            echo $OUTPUT->notification(get_string('login_confirmed', 'auth_qrcode'), 'success', false);
        }
    } else {
        echo $OUTPUT->notification(get_string('expired_or_rejected', 'auth_qrcode'), 'error', false);
    }
    echo $OUTPUT->footer();
    exit;
}

// Show login successful message.
if (intval($USER->id) === $qrcode->get('userid') && $qrcode->get('status') === qrcode_status::LOGGED_IN) {
    echo $OUTPUT->notification(get_string('login_successful', 'auth_qrcode'), 'success', false);
    echo $OUTPUT->footer();
    exit;
}

// Mark the token as in use.
$success = $qrcode->set_in_use();
if (!$success) {
    echo $OUTPUT->notification(get_string('expired_or_rejected', 'auth_qrcode'), 'danger', false);
    echo $OUTPUT->footer();
    exit;
}

// Render confirmation page.
$tokeninfo = $qrcode->get_loginattempt_info();
$tokeninfo['sesskey'] = sesskey();
$tokeninfo['sitename'] = format_string($SITE->shortname);
echo $OUTPUT->render_from_template('auth_qrcode/confirmation', $tokeninfo);

echo $OUTPUT->footer();
