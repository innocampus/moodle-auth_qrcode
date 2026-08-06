/**
 * Periodic check for the status of the QR code authentication on the confirmation page.
 *
 * @module     auth_qrcode/confirm
 * @copyright  2026 Lars Bonczek (@innoCampus, TU Berlin)
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';

/**
 * Login atttempt token.
 * @type {String}
 */
let token;

/**
 * Interval ID.
 * @type {number}
 */
let checkInterval;

/**
 * Set up the periodic check of the QR code authentication status.
 * @param {String} _token
 */
export function init(_token) {
    token = _token;
    checkInterval = setInterval(checkNow, 2000);
}

/**
 * Ask the server to check the status of the QR code authentication.
 */
async function checkNow() {
    const check = await Ajax.call([{
        methodname: 'auth_qrcode_check_login',
        args: {
            token: token
        }
    }])[0];
    if (check.status === 'not_authorized' || check.status === 'token_not_found' || check.status === 'logged_in') {
        // Reload page.
        clearInterval(checkInterval);
        window.location.replace(window.location.href);
    }
    return false;
}
