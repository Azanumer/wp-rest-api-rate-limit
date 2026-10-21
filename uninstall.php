<?php
// Exit if accessed directly.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wprl_options' );

global $wpdb;
// Drop any leftover counters/stats transients.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", '_transient_wprl_%' ) );
