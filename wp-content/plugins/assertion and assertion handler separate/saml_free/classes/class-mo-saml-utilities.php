<?php
/**
 * This file is part of miniOrange SAML plugin.
 *
 * The miniOrange SAML plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * miniOrange SAML plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with miniOrange SAML plugin.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package    miniorange-saml-20-single-sign-on
 * @author     miniOrange
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once dirname( __FILE__ ) . '/../includes/lib/mo-saml-xmlseclibs.php';
use \RobRichards\XMLSecLibs\Mo_SAML_XML_Security_Key;
use \RobRichards\XMLSecLibs\Mo_SAML_XML_Security_DSig;
use \RobRichards\XMLSecLibs\Mo_SAML_XML_Sec_Enc;
require_once dirname( __FILE__ ) . '/../classes/class-mo-saml-sso-utilities.php';


/**
 * This class contains collections of various static functions used across the plugin.
 */
class Mo_SAML_Utilities {

    /**
     * Generates Random ID of 21 characters.
     *
     * @return string
     */
    public static function mo_saml_generate_id() {
        return '_' . self::mo_saml_string_to_hex( Mo_SAML_Utilities::mo_saml_generate_random_bytes( 21 ) );
    }
    /**
     * Generates time stamp.
     *
     * @param  mixed $instant Store current time.
     * @return Date.
     */
    public static function mo_saml_generate_time_stamp( $instant = null ) {
        if ( null === $instant ) {
            $instant = time();
        }
        return gmdate( 'Y-m-d\TH:i:s\Z', $instant );
    }
    
    
/**
	 * Parse the NameID.
	 *
	 * @param  DOMElement $xml Contains an Xml value.
	 * @return string
	 */
	public static function mo_saml_parse_name_id( DOMElement $xml ) {
		//phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
		$ret = array( 'Value' => trim( $xml->textContent ) );

		foreach ( array( 'NameQualifier', 'SPNameQualifier', 'Format' ) as $attr ) {
			if ( $xml->hasAttribute( $attr ) ) {
				$ret[ $attr ] = $xml->getAttribute( $attr );
			}
		}

		return $ret;
	}
	
	
	/**
	 * Coverts String to Hex.
	 *
	 * @param  string $bytes Contains bytes.
	 * @return string
	 */
	public static function mo_saml_string_to_hex( $bytes ) {
	    $ret    = '';
	    $length = strlen( $bytes );
	    for ( $i = 0; $i < $length; $i++ ) {
	        $ret .= sprintf( '%02x', ord( $bytes[ $i ] ) );
	    }
	    return $ret;
	}
	
	/**
	 * Generates Random Bytes.
	 *
	 * @param   int $length Length of characters generating Random Bytes.
	 * @return string
	 */
	public static function mo_saml_generate_random_bytes( $length ) {
	    
	    return openssl_random_pseudo_bytes( $length );
	}
	
	
	
	
	
	/**
	 * Converts Date to Timestamp.
	 *
	 * @param  mixed $time Contains time value.
	 * @return string
	 */
	public static function mo_saml_xs_date_time_to_timestamp( $time ) {
		$matches = array();

		// We use a very strict regex to parse the timestamp.
		$regex = '/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?Z$/D';
		if ( preg_match( $regex, $time, $matches ) === 0 ) {
			echo sprintf( 'Invalid SAML2 timestamp passed to xsDateTimeToTimestamp: ' . esc_html( $time ) );
			exit;
		}

		// Extract the different components of the time from the  matches in the regex.
		// intval will ignore leading zeroes in the string.
		$year   = intval( $matches[1] );
		$month  = intval( $matches[2] );
		$day    = intval( $matches[3] );
		$hour   = intval( $matches[4] );
		$minute = intval( $matches[5] );
		$second = intval( $matches[6] );

		// We use gmmktime because the timestamp will always be given
		// in UTC.
		$ts = gmmktime( $hour, $minute, $second, $month, $day, $year );

		return $ts;
	}
		/**
	 * Validate the given array.
	 *
	 * @param  array $validate_fields_array contains fields to be validated.
	 * @return boolean
	 */
	public static function mo_saml_check_empty_or_null( $validate_fields_array ) {
		foreach ( $validate_fields_array as $fields ) {
			if ( ! isset( $fields ) || empty( $fields ) ) {
				return true;
			}
		}
		return false;
	}
	/**
	 * Block Access to WP site.
	 *
	 * @param  array $error_code contains error codes.
	 * @return void
	 */
	public static function mo_saml_die( $error_code ) {
		wp_die( 'We could not sign you in. Please contact your administrator with the following error code.<br><br>Error code: <b>' . esc_html( $error_code['code'] ) . '</b>', 'Error: ' . esc_html( $error_code['code'] ) );
	}
	/**
	 * Get the file contents.
	 *
	 * @param  string $file contains metadata file.
	 * @return string
	 */
	public static function mo_safe_file_get_contents( $file ) {
		//phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Required for handling runtime error during the file read operation.
		set_error_handler( 'Mo_SAML_Utilities::mo_handle_file_content_error' );
		if ( is_uploaded_file( $file ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Required for reading the file.
			$file = file_get_contents( $file );
		} else {
			$file = '';
		}
		restore_error_handler();
		return $file;
	}
	/**
	 * Checks if Curl Extension is installed or not.
	 *
	 * @return int
	 */
	public static function mo_saml_is_curl_installed() {
		if ( in_array( 'curl', get_loaded_extensions(), true ) ) {
			return 1;
		}
		return 0;
	}
	/**
	 * Checks if iconv Extension is installed or not.
	 *
	 * @return int
	 */
	public static function mo_saml_is_iconv_installed() {

		if ( in_array( 'iconv', get_loaded_extensions(), true ) ) {
			return 1;
		} else {
			return 0;
		}
	}
	/**
	 * Checks if openssl Extension is installed or not.
	 *
	 * @return int
	 */
	public static function mo_saml_is_openssl_installed() {

		if ( in_array( 'openssl', get_loaded_extensions(), true ) ) {
			return 1;
		} else {
			return 0;
		}
	}
	/**
	 * Checks if the DOM Extension is installed or not.
	 *
	 * @return int
	 */
	public static function mo_saml_is_dom_installed() {

		if ( in_array( 'dom', get_loaded_extensions(), true ) ) {
			return 1;
		} else {
			return 0;
		}
	}
	/**
	 * Returns SP Base URL.
	 *
	 * @return string
	 */
	public static function mo_saml_get_sp_base_url() {
		$sp_base_url = get_option( Mo_Saml_Options_Enum_Identity_Provider::SP_BASE_URL );

		if ( empty( $sp_base_url ) ) {
			$sp_base_url = site_url();
		}

		if ( substr( $sp_base_url, -1 ) === '/' ) {
			$sp_base_url = substr( $sp_base_url, 0, - 1 );
		}

		return $sp_base_url;
	}
	/**
	 * Returns SP Entity ID.
	 *
	 * @param  string $sp_base_url Base URL of the Plugin.
	 * @return string
	 */
	public static function mo_saml_get_sp_entity_id( $sp_base_url ) {
		$sp_entity_id = get_option( Mo_Saml_Options_Enum_Identity_Provider::SP_ENTITY_ID );

		if ( empty( $sp_entity_id ) ) {
			$sp_entity_id = $sp_base_url . '/wp-content/plugins/miniorange-saml-20-single-sign-on/';
		}

		return $sp_entity_id;
	}
	/**
	 * Checks if the SP is configured or not.
	 *
	 * @return bool
	 */
	public static function mo_saml_is_sp_configured() {
		$saml_login_url = get_option( Mo_Saml_Options_Enum_Service_Provider::LOGIN_URL );

		if ( empty( $saml_login_url ) ) {
			return 0;
		} else {
			return 1;
		}
	}
	/**
	 * Display run time error, which occured during the file reading.
	 *
	 * @param  string $errno contains error message.
	 * @return bool
	 */
	public static function mo_handle_file_content_error( $errno ) {
		if ( E_WARNING === $errno ) {
			update_option( 'mo_saml_message', 'Error: An error occurred while reading file content' );
			self::mo_saml_show_error_message();
			return true;
		} else {
			return false;
		}
	}
	/**
	 * Get the URL directory path for the plugin __FILE__ passed in.
	 *
	 * @return string
	 */
	public static function mo_saml_get_plugin_dir_url() {
		return plugin_dir_url( __FILE__ );
	}
	/**
	 * Checks whether its plugin page or any other page such as feedback page.
	 *
	 * @return bool
	 */
	public static function mo_saml_is_plugin_page() {
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$server_url = esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		} else {
			$server_url = '';
		}
		//phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Required to parse the Server URL.
		$query_str = parse_url( $server_url, PHP_URL_QUERY );
		$query_str = is_null( $query_str ) ? '' : $query_str;
		parse_str( $query_str, $query_params );
		//phpcs:ignore WordPress.Security.NonceVerification.Missing -- NonceVerification is not required here.
		if ( ( isset( $_POST['option'] ) && ( 'mo_skip_feedback' === $_POST['option'] || 'mo_feedback' === $_POST['option'] ) ) || ! empty( $query_params['page'] ) && strpos( $query_params['page'], 'mo_saml' ) !== false ) {
			return true;
		}
		return false;
	}
	/**
	 * Responsible for showing success message.
	 *
	 * @return void
	 */
	public static function mo_saml_show_error_message() {
	    remove_action( 'admin_notices', array( self::class, 'mo_saml_error_message' ) );
	    add_action( 'admin_notices', array( self::class, 'mo_saml_success_message' ) );
	}
	/**
	 * Responsible for showing error message.
	 *
	 * @return void
	 */
	public static function mo_saml_show_success_message() {
	    remove_action( 'admin_notices', array( self::class, 'mo_saml_success_message' ) );
	    add_action( 'admin_notices', array( self::class, 'mo_saml_error_message' ) );
	}
	/**
	 * Responsible for showing success message.
	 *
	 * @return void
	 */
	public static function mo_saml_success_message() {
	    $class        = 'error';
	    $message      = get_option( Mo_Saml_Options_Enum::SAML_MESSAGE );
	    $allowed_html = array(
	        'a'    => array(
	            'href'   => array(),
	            'target' => array(),
	        ),
	        'code' => array(),
	    );
	    echo '<div class="' . esc_html( $class ) . ' error_msg" style="display:none;"> <p>' . wp_kses( $message, $allowed_html ) . '</p></div>';
	}
	/**
	 * Responsible for showing error message.
	 *
	 * @return void
	 */
	public static function mo_saml_error_message() {
	    $class        = 'updated';
	    $message      = get_option( Mo_Saml_Options_Enum::SAML_MESSAGE );
	    $allowed_html = array(
	        'a'    => array(
	            'href'   => array(),
	            'target' => array(),
	        ),
	        'code' => array(),
	    );
	    echo '<div class="' . esc_html( $class ) . ' success_msg" style="display:none;"> <p>' . wp_kses( $message, $allowed_html ) . '</p></div>';
	}
	/**
	 * Makes an HTTP request to given url using post method and returns its response.
	 *
	 * @param  string $url endpoint where the HTTP request is made.
	 * @param  array  $args Request arguments.
	 * @return string
	 */
	
	public static function mo_saml_wp_remote_post( $url, $args = array() ) {
	    $response = wp_remote_post( $url, $args );
	    if ( ! is_wp_error( $response ) ) {
	        return $response['body'];
	    } else {
	        update_option( Mo_Saml_Options_Enum::SAML_MESSAGE, __( 'Unable to connect to the Internet. Please try again.', 'miniorange-saml-20-single-sign-on' ) );
	        ( new self() )->mo_saml_show_error_message();
	        return null;
	    }
	}
	
	/**
	 * Makes an HTTP Request using GET method and return its response.
	 *
	 * @param  string $url Endpoint where the HTTP request is made.
	 * @param  array  $args Request arguments.
	 */
	public static function mo_saml_wp_remote_get( $url, $args = array() ) {
	    $response = wp_remote_get( $url, $args );
	    if ( ! is_wp_error( $response ) ) {
	        return $response;
	    } else {
	        update_option( Mo_Saml_Options_Enum::SAML_MESSAGE, __( 'Unable to connect to the Internet. Please try again.', 'miniorange-saml-20-single-sign-on' ) );
	        ( new self() )->mo_saml_show_error_message();
	    }
	}
	
	
}
