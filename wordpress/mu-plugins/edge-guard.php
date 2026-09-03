<?php
/**
 * Plugin Name: Edge Guard
 * Description: Origin protection. Rejects every HTTP request that does not come from the edge with a valid X-Edge-Secret. As a mu-plugin it cannot be deactivated.
 * Version: 0.1.0
 */

// WP-CLI and cron do not run over HTTP and do not need the edge.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	return;
}
if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
	return;
}

// Fail closed: without a configured secret nothing is served.
if ( ! defined( 'EDGE_SHARED_SECRET' ) || EDGE_SHARED_SECRET === '' ) {
	http_response_code( 500 );
	header( 'Content-Type: text/plain; charset=utf-8' );
	header( 'Cache-Control: no-store' );
	echo "500\n\nEDGE_SHARED_SECRET is not configured.\n";
	exit;
}

$edge_guard_given = isset( $_SERVER['HTTP_X_EDGE_SECRET'] ) ? (string) $_SERVER['HTTP_X_EDGE_SECRET'] : '';

if ( ! hash_equals( EDGE_SHARED_SECRET, $edge_guard_given ) ) {
	http_response_code( 403 );
	header( 'Content-Type: text/plain; charset=utf-8' );
	header( 'Cache-Control: no-store' );
	echo "403 Forbidden\n\n";
	echo "This origin only accepts requests that come through the edge.\n";
	echo "Direct access would make the role header forgeable and is therefore blocked.\n";
	exit;
}

unset( $edge_guard_given );
