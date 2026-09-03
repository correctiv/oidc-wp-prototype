<?php
/**
 * Plugin Name: Example Role
 * Description: Reads the access level (none, limited, full) from the X-Example-Role header set by the edge and provides shortcodes for role-dependent content. Stores no user data and knows no identity.
 * Version: 0.1.0
 */

defined( 'ABSPATH' ) || exit;

/**
 * Ordering of the levels. A higher value includes the lower ones.
 *
 * @return array<string,int>
 */
function example_role_levels(): array {
	return array(
		'none'    => 0,
		'limited' => 1,
		'full'    => 2,
	);
}

/**
 * Current access level from the request header. Unknown values become "none".
 *
 * The header comes exclusively from Varnish, which overwrites whatever the client sent.
 * WordPress must therefore only be reachable through Varnish (network isolation).
 */
function example_role(): string {
	static $role = null;
	if ( null === $role ) {
		$raw  = isset( $_SERVER['HTTP_X_EXAMPLE_ROLE'] ) ? strtolower( trim( (string) $_SERVER['HTTP_X_EXAMPLE_ROLE'] ) ) : '';
		$role = array_key_exists( $raw, example_role_levels() ) ? $raw : 'none';
	}
	return $role;
}

function example_role_at_least( string $min ): bool {
	$levels = example_role_levels();
	if ( ! array_key_exists( $min, $levels ) ) {
		return false;
	}
	return $levels[ example_role() ] >= $levels[ $min ];
}

/**
 * Path of the current page, used as the return target after login.
 * Contains no user data; it is part of the page cached per role.
 */
function example_role_current_path(): string {
	$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
	if ( '' === $uri || '/' !== $uri[0] || str_starts_with( $uri, '//' ) ) {
		return '/';
	}
	return $uri;
}

/**
 * [example_role_content min="limited"]…[/example_role_content]
 * [example_role_content only="none,limited"]…[/example_role_content]
 */
add_shortcode(
	'example_role_content',
	function ( $atts, $content = '' ) {
		$atts = shortcode_atts(
			array(
				'min'  => '',
				'only' => '',
			),
			$atts,
			'example_role_content'
		);

		$show = true;
		if ( '' !== $atts['only'] ) {
			$allowed = array_map( 'trim', explode( ',', strtolower( $atts['only'] ) ) );
			$show    = in_array( example_role(), $allowed, true );
		} elseif ( '' !== $atts['min'] ) {
			$show = example_role_at_least( strtolower( $atts['min'] ) );
		}

		if ( ! $show ) {
			return '';
		}
		return do_shortcode( $content );
	}
);

/** [example_role_badge label="Access level"] */
add_shortcode(
	'example_role_badge',
	function ( $atts ) {
		$atts = shortcode_atts( array( 'label' => 'Access level' ), $atts, 'example_role_badge' );
		$role = example_role();
		return sprintf(
			'<span class="example-role-badge example-role-badge--%1$s">%2$s: <strong>%1$s</strong></span>',
			esc_attr( $role ),
			esc_html( $atts['label'] )
		);
	}
);

/** [example_login_link text="Log in"] */
add_shortcode(
	'example_login_link',
	function ( $atts ) {
		$atts = shortcode_atts( array( 'text' => 'Log in' ), $atts, 'example_login_link' );
		$href = '/auth/login?return=' . rawurlencode( example_role_current_path() );
		return sprintf( '<a class="example-role-link" href="%s">%s</a>', esc_url( $href ), esc_html( $atts['text'] ) );
	}
);

/** [example_logout_link text="Log out"] */
add_shortcode(
	'example_logout_link',
	function ( $atts ) {
		$atts = shortcode_atts( array( 'text' => 'Log out' ), $atts, 'example_logout_link' );
		return sprintf( '<a class="example-role-link" href="%s">%s</a>', esc_url( '/auth/logout' ), esc_html( $atts['text'] ) );
	}
);

/**
 * Cache headers for anonymous front-end responses. The edge uses s-maxage as the TTL.
 * Vary is documentary only: the edge caches explicitly by role in its key.
 */
add_action(
	'send_headers',
	function () {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		$ttl = defined( 'EXAMPLE_ROLE_CACHE_TTL' ) ? (int) EXAMPLE_ROLE_CACHE_TTL : 60;
		header( 'Cache-Control: public, s-maxage=' . $ttl );
		header( 'Vary: X-Example-Role' );
	}
);

/** Minimal styling for the demo page. */
add_action(
	'wp_head',
	function () {
		echo '<style>
.example-role-badge{display:inline-block;padding:.25em .75em;border-radius:1em;background:#e5e7eb;font-size:.9em}
.example-role-badge--limited{background:#fde68a}
.example-role-badge--full{background:#86efac}
.example-role-link{display:inline-block;padding:.4em 1em;border:1px solid currentColor;border-radius:.4em;text-decoration:none}
</style>';
	}
);
