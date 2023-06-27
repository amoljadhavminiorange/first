<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'upgrade_plugin' );

/** Database username */
define( 'DB_USER', 'root' );

/** Database password */
define( 'DB_PASSWORD', '' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'W|&o,V?=EcDAQDWLjGuZin7^^0|Y6K2+S;gu#g<N*CeYIZRe_-@=2p|)jBr-&5#O' );
define( 'SECURE_AUTH_KEY',  'SidteY)v!t[kVB]`F2t[%3D}34>2D7O@L+a]Ik_R,{dwK6kfh$#1Tx=gn BC&DB$' );
define( 'LOGGED_IN_KEY',    'Z*}4p0DW(6BVcW4q<%09a6:7P+fQ[utPu2-ZHJE_HjUm[:*QR-wR/JeiRPc1rX:R' );
define( 'NONCE_KEY',        '-G`>M^nK{PJh312WTCJ%0zVK,7mO*13y)d#,<Eu}nIhxV;}RhJRqJLb)8^IIwFu,' );
define( 'AUTH_SALT',        'ud#U8TtkEt1C8Y7=CIGX9p%8e@>5N8^&`a<0k[[Q4vr`ZT*hKB?!#quF%ab4WTpd' );
define( 'SECURE_AUTH_SALT', 'U5X1+hX6+;yY_{Pr<b<hlR]hUFZI{B{8CE#G}*Z5+fQ.$W.,?)_u-HV{P%n@u<%?' );
define( 'LOGGED_IN_SALT',   'JRhp:vgTYh8$xk<y:82L&ju<H3b-DZ,OW%YS?;.e`Q=uFvQ%y+PfWS$[4B?u6<B|' );
define( 'NONCE_SALT',       'w%%R3YcbW|XacbiRTb~Nc|]pc]/7DwF|1,{#|ly5UXS4,.{L&WD98KFJ^roueU9$' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/documentation/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
