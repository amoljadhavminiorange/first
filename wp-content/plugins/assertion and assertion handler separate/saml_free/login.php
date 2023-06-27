<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName -- cannot change main file's name
/**
 * Plugin Name: miniOrange SSO using SAML 2.0
 * Plugin URI: https://miniorange.com/
 * Description: miniOrange SAML plugin allows sso/login using Azure, Azure B2C, Okta, ADFS, Keycloak, Onelogin, Salesforce, Google Apps (Gsuite), Salesforce, Shibboleth, Centrify, Ping, Auth0 and other Identity Providers. It acts as a SAML Service Provider which can be configured to establish a trust between the plugin and IDP to securely authenticate and login the user to WordPress site.
 * Version: 5.0.3
 * Author: miniOrange
 * Author URI: https://miniorange.com/
 * License: MIT/Expat
 * License URI: https://docs.miniorange.com/mit-license
 * Text Domain: miniorange-saml-20-single-sign-on
 *
 * @package miniorange-saml-20-single-sign-on
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once 'handlers/class-mo-saml-main-handler.php';

/**
 * The Main class of the miniOrange SAML SSO Plugin.
 */
class Saml_Mo_Login {
}
