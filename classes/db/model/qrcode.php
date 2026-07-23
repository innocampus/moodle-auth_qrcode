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

namespace auth_qrcode\db\model;

use auth_qrcode\event\logged_in;
use auth_qrcode\event\login_authorized;
use core\exception\coding_exception;
use core\exception\moodle_exception;
use core\invalid_persistent_exception;
use core\persistent;
use dml_exception;
use Random\RandomException;
use stdClass;

/**
 * Persistent model representing a QR code login attempt.
 *
 * This class handles the storage and retrieval of QR code tokens and their
 * associated session and user information.
 *
 * @package   auth_qrcode
 * @author    Stefan Dani (stefan.dani@ffhs.ch)
 * @copyright 2026 MoodleMootDACH
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class qrcode extends persistent {
    /**
     * {@inheritDoc}
     */
    const TABLE = 'auth_qrcode';
    /** @var int Maximum number of failed attempts when entering the confirmation code. */
    const CONFIRMATIONCODE_ATTEMPTS = 3;
    /** @var int Number of digits in confirmation code. */
    const CONFIRMATIONCODE_LENGTH = 4;

    /**
     * Creates a new QR code login record.
     *
     * @param string $token The unique token.
     * @param string $sid The session ID string that requested the QR code.
     * @param string|null $useragent The user agent string to parse for OS and browser. Defaults to current UA.
     * @param int|null $duration Optional duration in seconds from now. If not set it defaults to value of
     * auth_qrcode/expirationtime setting.
     * @return self|null The created persistent object, or null if token already exists.
     * @throws coding_exception
     * @throws invalid_persistent_exception
     * @throws dml_exception
     */
    public static function create_record(
        string $token,
        string $sid,
        ?string $useragent = null,
        ?int $duration = null
    ): self|false {
        $existing = self::get_record([
            'token' => $token,
        ]);

        if ($existing) {
            return false;
        }

        $sessionid = self::get_session_id($sid);
        if ($sessionid === null) { // Check like this because sessionid could be 0 (zero).
            return false;
        }

        $ua = $useragent ?? \core_useragent::get_user_agent_string() ?: '';
        $env = self::detect_environment($ua);

        $record = new self();
        $record->set('token', $token);
        $record->set('initial_sessionid', $sessionid);
        $record->set('requester_os', $env['os']);
        $record->set('requester_browser', $env['browser']);
        $record->set('status', qrcode_status::CREATED);
        $record->set('failedattempts', 0);
        $record->set('timecreated', time());
        $record->set('timeexpires', self::calculate_expiry($duration));
        $record->create();

        return $record;
    }

    /**
     * Sets the user ID for this login attempt and updates status to authorized. Also resets the expiration timer.
     *
     * @param int $userid
     * @param int|null $duration Optional expiration duration in seconds from now. If not set it defaults to value of
     * auth_qrcode/expirationtime setting.
     * @return bool true if marked as allowed, or false if wrong state or expired.
     * @throws coding_exception
     * @throws dml_exception
     * @throws invalid_persistent_exception
     * @throws RandomException
     */
    public function allow(int $userid, ?int $duration = null): bool {
        if ($this->is_expired() || $this->get('status') !== qrcode_status::IN_USE) {
            return false;
        }
        $this->set('userid', $userid);
        $this->set('status', qrcode_status::ALLOWED);
        if (get_config('auth_qrcode', 'useconfirmationcode')) {
            $this->set('confirmationcode', self::generate_confirmation_code());
            $this->set('failedattempts', 0);
        }
        $this->set('timeexpires', self::calculate_expiry($duration)); // Extend timer.
        $this->update();
        $event = login_authorized::create([
            'userid' => $userid,
            'objectid' => $userid,
            'other' => ['token' => $this->get('token')],
        ]);
        $event->trigger();
        return true;
    }

    /**
     * Denies this QR code login attempt.
     *
     * @return bool true if marked as denied, or false if wrong state or expired.
     * @throws coding_exception
     * @throws invalid_persistent_exception
     * @throws dml_exception
     */
    public function deny(): bool {
        global $USER;
        // It's possible to deny allowed login requests waiting for confirmation.
        if ($this->is_expired() || !in_array($this->get('status'), [qrcode_status::IN_USE, qrcode_status::ALLOWED])) {
            return false;
        }

        // Only the user who authorized the login can deny it if it has already been allowed.
        if ($this->get('status') === qrcode_status::ALLOWED && intval($USER->id) !== $this->get('userid')) {
            return false;
        }

        $this->set('status', qrcode_status::DENIED);
        $this->set('timeexpires', self::calculate_expiry(10)); // Set expire to 10 seconds.
        $this->update();
        return true;
    }

    /**
     * Marks the login attempt as in use. Also resets the expiration timer.
     *
     * @param int|null $duration Optional expiration duration in seconds from now. If not set it defaults to value of
     * auth_qrcode/expirationtime setting.
     * @return bool true if marked as in use, or false if wrong state or expired.
     * @throws coding_exception
     * @throws dml_exception
     * @throws invalid_persistent_exception
     */
    public function set_in_use(?int $duration = null): bool {
        if ($this->is_expired() || $this->get('status') !== qrcode_status::CREATED) {
            return false;
        }

        $this->set('status', qrcode_status::IN_USE);
        $this->set('timeexpires', self::calculate_expiry($duration)); // Extend timer.
        $this->update();
        return true;
    }

    /**
     * Retrieves information about the login attempt.
     *
     * @return array Array with ip, os, and browser.
     * @throws coding_exception
     * @throws dml_exception
     * @throws invalid_persistent_exception
     */
    public function get_loginattempt_info(): array {
        global $DB;
        $session = $DB->get_record('sessions', ['id' => $this->get('initial_sessionid')], 'lastip');

        return [
            'ip' => $session ? $session->lastip : 'Unknown',
            'os' => $this->get('requester_os'),
            'browser' => $this->get('requester_browser'),
        ];
    }

    /**
     * Check whether the confirmation code that was entered is valid. Increments the failed attempts count if an invalid (non-null)
     * code is passed.
     *
     * @param string|null $confirmationcode
     * @return bool
     * @throws coding_exception
     * @throws dml_exception
     * @throws invalid_persistent_exception
     */
    public function check_confirmationcode(string|null $confirmationcode): bool {
        if (!get_config('auth_qrcode', 'useconfirmationcode')) {
            return true;
        }
        if (is_null($confirmationcode)) {
            return false;
        }
        if ($this->is_expired() || $this->get('status') !== qrcode_status::ALLOWED) {
            return false;
        }
        $failed = $this->get('failedattempts');
        if ($this->get('confirmationcode') !== $confirmationcode) {
            $this->set('failedattempts', $failed + 1);
            if ($failed + 1 >= self::CONFIRMATIONCODE_ATTEMPTS) {
                $this->set('status', qrcode_status::DENIED);
            }
            $this->update();
            return false;
        }
        return true;
    }

    /**
     * Get the remaining number of attempts for a QR code confirmation code.
     *
     * This does not check the state of the QR login attempt.
     *
     * @return int Remaining number of attempts.
     * @throws coding_exception
     * @throws dml_exception
     */
    public function get_remaining_attempts(): int {
        $failed = $this->get('failedattempts');
        return max(0, self::CONFIRMATIONCODE_ATTEMPTS - $failed);
    }

    /**
     * Checks if login has been authorized.
     *
     * @return bool Whether login is allowed.
     * @throws coding_exception
     * @throws dml_exception
     */
    public function is_login_authorized(): bool {
        if ($this->is_expired()) {
            return false;
        }
        return $this->get('status') === qrcode_status::ALLOWED;
    }

    /**
     * Checks if this is the initial session.
     *
     * @param string $sid The session ID string.
     * @return bool
     * @throws \coding_exception
     * @throws dml_exception
     */
    public function is_initial_session(string $sid): bool {
        $sessionid = self::get_session_id($sid);
        if ($sessionid === null) { // Check like this because sessionid could be 0 (zero).
            return false;
        }
        return $this->get('initial_sessionid') === $sessionid;
    }

    /**
     * Completes the login for the current session.
     *
     * This checks whether the login attempt has been authorized, but it does NOT check whether the correct confirmation code has
     * been provided.
     *
     * @throws moodle_exception
     * @throws coding_exception
     */
    public function perform_login(): bool {
        if (!$this->is_login_authorized() || !$this->is_initial_session(session_id())) {
            return false;
        }
        $user = $this->get_user_record();
        if (!$user) {
            return false;
        }

        // Perform login.
        complete_user_login($user, ['auth_qrcode_login' => true]);

        // Update record.
        $this->set('status', qrcode_status::LOGGED_IN);
        $this->set('timeexpires', self::calculate_expiry(10)); // Set expire to 10 seconds.
        $this->update();

        // Trigger event.
        $event = logged_in::create([
            'userid' => $user->id,
            'objectid' => $user->id,
            'other' => ['token' => $this->get('token')],
        ]);
        $event->trigger();
        return true;
    }

    /**
     * Returns the user associated with this QR login attempt.
     *
     * @return stdClass|null
     * @throws coding_exception
     * @throws dml_exception
     */
    public function get_user_record(): ?stdClass {
        global $DB;

        $userid = $this->get('userid');
        if (!$userid) {
            return null;
        }
        return $DB->get_record('user', ['id' => $userid]) ?: null;
    }

    /**
     * Checks if this record is expired and deletes it if so.
     *
     * @return bool True if expired, false otherwise.
     * @throws coding_exception
     */
    public function is_expired(): bool {
        if ($this->get('timeexpires') < time()) {
            $this->delete();
            return true;
        }
        return false;
    }

    /**
     * Find a QR login attempt by token.
     *
     * @param string $token The token to search for.
     * @return qrcode|null QR login attempt or null if not found or expired.
     * @throws coding_exception
     */
    public static function get_by_token(string $token): ?qrcode {
        $record = self::get_record(['token' => $token]);
        if (!$record || $record->is_expired()) {
            return null;
        }
        return $record;
    }

    /**
     * Delete expired records.
     *
     * @param int|null $timestamp The timestamp to compare against. If null, current time is used.
     * @return void
     * @throws dml_exception
     */
    public static function delete_expired(?int $timestamp = null): void {
        global $DB;
        $timestamp = $timestamp ?? time();
        $DB->delete_records_select(self::TABLE, 'timeexpires < ?', [$timestamp]);
    }

    /**
     * Retrieves the database ID for a session ID string.
     *
     * @param string $sid The session ID string.
     * @return int|null The session database ID or null if not found.
     * @throws dml_exception
     */
    private static function get_session_id(string $sid): ?int {
        global $DB;
        $session = $DB->get_record('sessions', ['sid' => $sid], 'id');
        return $session ? (int) $session->id : null;
    }

    /**
     * Calculates an expiry timestamp.
     *
     * @param int|null $duration Optional duration in seconds from now. Defaults to value of auth_qrcode/expirationtime setting.
     * @return int The calculated expiry timestamp.
     * @throws dml_exception
     */
    private static function calculate_expiry(?int $duration = null): int {
        if ($duration === null) {
            $duration = intval(get_config('auth_qrcode', 'expirationtime') ?: 60);
        }
        return time() + $duration;
    }

    /**
     * Generates a numeric confirmation code.
     *
     * @param int $digits The number of digits to generate.
     * @return string The confirmation code (left-padded with zeros).
     * @throws RandomException
     */
    private static function generate_confirmation_code(int $digits = self::CONFIRMATIONCODE_LENGTH): string {
        $max = pow(10, $digits) - 1;
        $code = random_int(0, $max);
        return str_pad(strval($code), $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Detects the OS and Browser from a User Agent string.
     *
     * This avoids affecting the global core_useragent singleton.
     *
     * @param string $ua The user agent string.
     * @return array Contains 'os' and 'browser' keys.
     */
    private static function detect_environment(string $ua): array {
        $browser = 'Unknown';
        if (preg_match('/Edg\/|Edge\//i', $ua)) {
            $browser = 'Edge';
        } else if (preg_match('/Chrome|CriOS/i', $ua)) {
            $browser = 'Chrome';
        } else if (preg_match('/Firefox|Iceweasel/i', $ua)) {
            $browser = 'Firefox';
        } else if (preg_match('/Safari/i', $ua) && !preg_match('/Chrome|CriOS/i', $ua)) {
            $browser = 'Safari';
        } else if (preg_match('/Opera|OPR\//i', $ua)) {
            $browser = 'Opera';
        } else if (preg_match('/MSIE|Trident\//i', $ua)) {
            $browser = 'Internet Explorer';
        }

        $os = 'Unknown';
        if (preg_match('/iPhone|iPad|iPod/i', $ua)) {
            $os = 'iOS';
        } else if (preg_match('/Android/i', $ua)) {
            $os = 'Android';
        } else if (preg_match('/Windows/i', $ua)) {
            $os = 'Windows';
        } else if (preg_match('/Macintosh|Mac OS X/i', $ua)) {
            $os = 'Mac OS';
        } else if (preg_match('/Linux/i', $ua)) {
            $os = 'Linux';
        }

        return ['os' => $os, 'browser' => $browser];
    }

    /**
     * Internal getter for status.
     *
     * @return qrcode_status
     * @throws coding_exception
     */
    protected function get_status(): qrcode_status {
        return qrcode_status::from($this->raw_get('status'));
    }

    /**
     * Internal setter for status.
     *
     * @param qrcode_status $status
     * @return self
     * @throws coding_exception
     */
    protected function set_status(qrcode_status $status): self {
        return $this->raw_set('status', $status->value);
    }

    /**
     * {@inheritDoc}
     */
    protected static function define_properties(): array {
        return [
            'token' => ['type' => PARAM_ALPHANUM],
            'initial_sessionid' => ['type' => PARAM_INT],
            'status' => ['type' => PARAM_ALPHAEXT],
            'userid' => ['type' => PARAM_INT, 'null' => NULL_ALLOWED, 'default' => null],
            'confirmationcode' => ['type' => PARAM_ALPHANUM, 'null' => NULL_ALLOWED, 'default' => null],
            'failedattempts' => ['type' => PARAM_INT],
            'timecreated' => ['type' => PARAM_INT],
            'timeexpires' => ['type' => PARAM_INT],
            'requester_os' => ['type' => PARAM_TEXT],
            'requester_browser' => ['type' => PARAM_TEXT],
        ];
    }
}
