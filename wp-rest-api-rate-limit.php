<?php
/**
 * Plugin Name:       WP REST API Rate Limit
 * Description:       Per-IP rate limiting for the WordPress REST API — stricter buckets for auth-sensitive routes, 429 + Retry-After, no dependencies.
 * Version:           1.0.0
 * Author:            Azan Umer
 * License:           MIT
 * Text Domain:       wprl
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPRL_VERSION', '1.0.0' );
define( 'WPRL_PREFIX', 'wprl_' );

/* ---------------------------------------------------------------------------
 * Options
 * ------------------------------------------------------------------------- */
function wprl_get_options() {
	$defaults = array(
		'general_limit' => 120,  // requests per window, all routes
		'strict_limit'  => 30,   // requests per window, auth-sensitive routes
		'window'        => 60,   // window in seconds
		'excluded'      => '',   // one IP or CIDR per line
		'bypass_admin'  => 1,    // skip users who can manage_options
	);
	$opts = get_option( 'wprl_options', array() );
	return wp_parse_args( is_array( $opts ) ? $opts : array(), $defaults );
}

/* ---------------------------------------------------------------------------
 * Client IP (filterable for sites behind a trusted proxy / Cloudflare)
 * ------------------------------------------------------------------------- */
function wprl_client_ip() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
	/**
	 * Filter the client IP used for rate limiting.
	 * Only trust X-Forwarded-For / CF-Connecting-IP here if you terminate TLS
	 * at a proxy you control — blindly trusting it lets attackers rotate IPs.
	 */
	return apply_filters( 'wprl_client_ip', $ip );
}

/**
 * CIDR / exact-IP match, IPv4 + IPv6.
 */
function wprl_ip_in_cidr( $ip, $cidr ) {
	if ( strpos( $cidr, '/' ) === false ) {
		return strtolower( $ip ) === strtolower( $cidr );
	}
	list( $subnet, $bits ) = explode( '/', $cidr, 2 );
	$bits = (int) $bits;
	$ip_bin     = @inet_pton( $ip );
	$subnet_bin = @inet_pton( $subnet );
	if ( $ip_bin === false || $subnet_bin === false || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
		return false;
	}
	$bytes     = (int) ( $bits / 8 );
	$remainder = $bits % 8;
	if ( substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) {
		return false;
	}
	if ( $remainder > 0 ) {
		$mask   = chr( 256 - ( 1 << ( 8 - $remainder ) ) );
		$ip_b   = $ip_bin[ $bytes ];
		$sub_b  = $subnet_bin[ $bytes ];
		if ( ( $ip_b & $mask ) !== ( $sub_b & $mask ) ) {
			return false;
		}
	}
	return true;
}

function wprl_is_excluded( $ip, $opts ) {
	$lines = preg_split( '/\r?\n/', (string) $opts['excluded'] );
	foreach ( $lines as $line ) {
		$line = trim( $line );
		if ( $line !== '' && wprl_ip_in_cidr( $ip, $line ) ) {
			return true;
		}
	}
	return false;
}

/* ---------------------------------------------------------------------------
 * Bucketing: auth-sensitive routes get the strict limit.
 * ------------------------------------------------------------------------- */
function wprl_bucket_for_route( $route ) {
	// User enumeration, comment spam, JWT/token endpoints — the usual targets.
	if ( preg_match( '#^/wp/v2/(users|comments)|jwt|token|auth#i', $route ) ) {
		return 'strict';
	}
	return 'general';
}

/* ---------------------------------------------------------------------------
 * Enforcement on rest_pre_dispatch — returning WP_Error short-circuits
 * the request with our 429.
 * ------------------------------------------------------------------------- */
add_filter( 'rest_pre_dispatch', 'wprl_check', 10, 3 );
function wprl_check( $result, $server, $request ) {
	if ( $result !== null ) {
		return $result; // another plugin already short-circuited
	}
	$opts = wprl_get_options();
	$ip   = wprl_client_ip();

	if ( $opts['bypass_admin'] && current_user_can( 'manage_options' ) ) {
		return null;
	}
	if ( wprl_is_excluded( $ip, $opts ) ) {
		return null;
	}

	$route  = $request->get_route();
	$bucket = wprl_bucket_for_route( $route );
	$limit  = $bucket === 'strict' ? (int) $opts['strict_limit'] : (int) $opts['general_limit'];
	$window = max( 10, (int) $opts['window'] );

	$key   = WPRL_PREFIX . $bucket . '_' . md5( $ip );
	$state = get_transient( $key );
	$now   = time();

	if ( ! is_array( $state ) || $now - $state['start'] >= $window ) {
		$state = array( 'start' => $now, 'count' => 0 );
	}
	$state['count']++;
	set_transient( $key, $state, $window );

	if ( $state['count'] > $limit ) {
		$retry = $window - ( $now - $state['start'] );
		// Stash for the header hook below.
		$GLOBALS['wprl_retry_after'] = max( 1, $retry );

		// Daily violation counter (cheap stats for the settings page).
		$day_key = WPRL_PREFIX . 'violations_' . gmdate( 'Y-m-d' );
		set_transient( $day_key, (int) get_transient( $day_key ) + 1, DAY_IN_SECONDS );

		return new WP_Error(
			'wprl_rate_limited',
			sprintf( 'Too many requests. Try again in %d seconds.', max( 1, $retry ) ),
			array( 'status' => 429 )
		);
	}
	return null;
}

/* ---------------------------------------------------------------------------
 * Retry-After header on our 429s.
 * ------------------------------------------------------------------------- */
add_filter( 'rest_pre_serve_request', 'wprl_retry_after_header', 10, 4 );
function wprl_retry_after_header( $served, $result, $request, $server ) {
	if ( is_wp_error( $result ) && $result->get_error_code() === 'wprl_rate_limited'
		&& isset( $GLOBALS['wprl_retry_after'] ) ) {
		$server->send_header( 'Retry-After', (string) (int) $GLOBALS['wprl_retry_after'] );
	}
	return $served;
}

/* ---------------------------------------------------------------------------
 * Admin: Settings → REST Rate Limit
 * ------------------------------------------------------------------------- */
add_action( 'admin_menu', 'wprl_admin_menu' );
function wprl_admin_menu() {
	add_options_page(
		'REST Rate Limit',
		'REST Rate Limit',
		'manage_options',
		'wprl',
		'wprl_admin_page'
	);
}

function wprl_admin_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Unauthorized' );
	}
	$opts = wprl_get_options();

	if ( isset( $_POST['wprl_save'] ) && check_admin_referer( 'wprl_settings' ) ) {
		$opts['general_limit'] = max( 1, (int) $_POST['wprl_general_limit'] );
		$opts['strict_limit']  = max( 1, (int) $_POST['wprl_strict_limit'] );
		$opts['window']        = max( 10, min( 3600, (int) $_POST['wprl_window'] ) );
		$opts['excluded']      = sanitize_textarea_field( wp_unslash( $_POST['wprl_excluded'] ) );
		$opts['bypass_admin']  = isset( $_POST['wprl_bypass_admin'] ) ? 1 : 0;
		update_option( 'wprl_options', $opts );
		echo '<div class="notice notice-success"><p>Settings saved.</p></div>';
	}

	if ( isset( $_POST['wprl_reset'] ) && check_admin_referer( 'wprl_reset' ) ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", '_transient_' . WPRL_PREFIX . '%' ) );
		echo '<div class="notice notice-success"><p>All rate-limit counters cleared.</p></div>';
	}

	$violations = (int) get_transient( WPRL_PREFIX . 'violations_' . gmdate( 'Y-m-d' ) );
	?>
	<div class="wrap">
		<h1>REST API Rate Limit</h1>
		<p>Requests blocked today: <strong><?php echo $violations; ?></strong></p>
		<form method="post">
			<?php wp_nonce_field( 'wprl_settings' ); ?>
			<table class="form-table">
				<tr>
					<th><label for="wprl_general_limit">General limit</label></th>
					<td><input type="number" id="wprl_general_limit" name="wprl_general_limit" value="<?php echo (int) $opts['general_limit']; ?>" min="1" class="small-text"> requests per window (all routes)</td>
				</tr>
				<tr>
					<th><label for="wprl_strict_limit">Strict limit</label></th>
					<td><input type="number" id="wprl_strict_limit" name="wprl_strict_limit" value="<?php echo (int) $opts['strict_limit']; ?>" min="1" class="small-text"> requests per window (auth-sensitive routes: <code>/wp/v2/users</code>, comments, JWT/token)</td>
				</tr>
				<tr>
					<th><label for="wprl_window">Window</label></th>
					<td><input type="number" id="wprl_window" name="wprl_window" value="<?php echo (int) $opts['window']; ?>" min="10" max="3600" class="small-text"> seconds</td>
				</tr>
				<tr>
					<th><label for="wprl_excluded">Excluded IPs</label></th>
					<td><textarea id="wprl_excluded" name="wprl_excluded" rows="4" cols="40" placeholder="203.0.113.10&#10;198.51.100.0/24"><?php echo esc_textarea( $opts['excluded'] ); ?></textarea>
					<p class="description">One IP or CIDR per line (IPv4 + IPv6).</p></td>
				</tr>
				<tr>
					<th><label for="wprl_bypass_admin">Admin bypass</label></th>
					<td><label><input type="checkbox" id="wprl_bypass_admin" name="wprl_bypass_admin" value="1" <?php checked( $opts['bypass_admin'], 1 ); ?>> Don't rate-limit administrators</label></td>
				</tr>
			</table>
			<?php submit_button( 'Save Settings', 'primary', 'wprl_save' ); ?>
		</form>
		<h2>Reset counters</h2>
		<form method="post">
			<?php wp_nonce_field( 'wprl_reset' ); ?>
			<?php submit_button( 'Clear All Counters', 'secondary', 'wprl_reset' ); ?>
		</form>
		<p class="description">Developers: filter <code>wprl_client_ip</code> to trust a proxy header (only behind a proxy you control).</p>
	</div>
	<?php
}
