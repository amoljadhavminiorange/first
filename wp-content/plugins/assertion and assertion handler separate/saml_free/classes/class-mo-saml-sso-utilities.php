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
require_once dirname( __FILE__ ) . '/../classes/class-mo-saml-utilities.php';


/**
 * This class contains collections of various static functions used across the plugin.
 */
class Mo_SAML_SSO_Utilities {
    
	/**
	 * Querying the SAML Response.
	 *
	 * @param  DOMNode $node Instance of DOMNode.
	 * @param  string  $query Contains value to be checked in the SAML Response e.g. Issuer.
	 * @return array
	 */
	public static function mo_saml_xp_query( DOMNode $node, $query ) {
		static $xp_cache = null;

		if ( $node instanceof DOMDocument ) {
			$doc = $node;
		} else {
			//phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMNode class.
			$doc = $node->ownerDocument;
		}

		if ( null === $xp_cache || ! $xp_cache->document->isSameNode( $doc ) ) {
			$xp_cache = new DOMXPath( $doc );
			$xp_cache->registerNamespace( 'soap-env', 'http://schemas.xmlsoap.org/soap/envelope/' );
			$xp_cache->registerNamespace( 'saml_protocol', 'urn:oasis:names:tc:SAML:2.0:protocol' );
			$xp_cache->registerNamespace( 'saml_assertion', 'urn:oasis:names:tc:SAML:2.0:assertion' );
			$xp_cache->registerNamespace( 'saml_metadata', 'urn:oasis:names:tc:SAML:2.0:metadata' );
			$xp_cache->registerNamespace( 'ds', 'http://www.w3.org/2000/09/xmldsig#' );
			$xp_cache->registerNamespace( 'xenc', 'http://www.w3.org/2001/04/xmlenc#' );
		}

		$results = $xp_cache->query( $query, $node );
		$ret     = array();
		for ( $i = 0; $i < $results->length; $i++ ) {
			$ret[ $i ] = $results->item( $i );
		}

		return $ret;
	}
    /**
     * Create SAML Request.
     *
     * @param  string $acs_url Endpoint on the SP where the IDP will redirect to with its authentication response.
     * @param  string $issuer An Entity ID which uniquely identities the SP.
     * @param  bool   $force_authn It will prompt users to enter their credentials on every login request.
     * @return string
     */
    public static function mo_saml_create_authn_request( $acs_url, $issuer, $force_authn = 'false' ) {
        $saml_nameid_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
        $request_xml_str    = '<?xml version="1.0" encoding="UTF-8"?>' .
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="' . Mo_SAML_Utilities::mo_saml_generate_id() .
            '" Version="2.0" IssueInstant="' . Mo_SAML_Utilities::mo_saml_generate_time_stamp() . '"';
        if ( 'true' === $force_authn ) {
            $request_xml_str .= ' ForceAuthn="true"';
        }
        $request_xml_str .= ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="' . $acs_url .
        '" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' . $issuer .
        '</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="' . $saml_nameid_format . '"/></samlp:AuthnRequest>';
        
        $deflated_str = gzdeflate( $request_xml_str );
        //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Require to encode the SAML Request.
        $base64_encoded_str = base64_encode( $deflated_str );
        //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.urlencode_urlencode -- Require when encoding string to be used in query part of URL.
        $url_encoded = urlencode( $base64_encoded_str );
        update_option( Mo_Saml_Options_Test_Configuration::SAML_REQUEST, $base64_encoded_str );
        
        return $url_encoded;
    }
    /**
     * Extract strings from Assertion.
     *
     * @param  DOMElement $parent Instance of DOMElement.
     * @param  string     $namespace_url Contains namespace value.
     * @param  string     $local_name Contains AuthenticatingAuthority or Audience Value.
     * @return array
     */
    public static function mo_saml_extract_strings( DOMElement $parent, $namespace_url, $local_name ) {
        $ret = array();
        //phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
        for ( $node = $parent->firstChild; null !== $node; $node = $node->nextSibling ) {
            //phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
            if ( $node->namespaceURI !== $namespace_url || $node->localName !== $local_name ) {
                continue;
            }
            //phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
            $ret[] = trim( $node->textContent );
        }
        
        return $ret;
    }
    /**
     * Validate the SAML Response.
     *
     * @param  DOMElement $root Instance of DOMElement.
     * @return array|bool
     */
    public static function mo_saml_validate_element( DOMElement $root ) {
        /* Create an XML security object. */
        $obj_xml_sec_dsig = new Mo_SAML_XML_Security_DSig();
        
        /* Both SAML messages and SAML assertions use the 'ID' attribute. */
        $obj_xml_sec_dsig->id_keys[] = 'ID';
        
        /* Locate the XMLDSig Signature element to be used. */
        $signature_element = self::mo_saml_xp_query( $root, './ds:Signature' );
        
        $signature_length = count( $signature_element );
        
        if ( 0 === $signature_length ) {
            /* We don't have a signature element to validate. */
            return false;
        } elseif ( $signature_length > 1 ) {
            echo sprintf( 'XMLSec: more than one signature element in root.' );
            exit;
        }
        
        $signature_element          = $signature_element[0];
        $obj_xml_sec_dsig->sig_node = $signature_element;
        
        try {
            /* Canonicalize the XMLDSig SignedInfo element in the message. */
            $obj_xml_sec_dsig->canonicalize_signed_info();
            
            /* Validate referenced xml nodes. */
            if ( ! $obj_xml_sec_dsig->validate_reference() ) {
                echo sprintf( 'XMLSec: digest validation failed' );
                exit;
            }
        } catch ( Exception $exception ) {
            wp_die( 'We could not sign you in. Please contact your administrator.', 'Invalid SAML Response' );
        }
        
        /* Check that $root is one of the signed nodes. */
        $root_signed = false;
        foreach ( $obj_xml_sec_dsig->get_validated_nodes() as $signed_node ) {
            if ( $signed_node->isSameNode( $root ) ) {
                $root_signed = true;
                break;
                //phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
            } elseif ( $root->parentNode instanceof DOMDocument && $signed_node->isSameNode( $root->ownerDocument ) ) {
                /* $root is the root element of a signed document. */
                $root_signed = true;
                break;
            }
        }
        
        if ( ! $root_signed ) {
            echo sprintf( 'XMLSec: The root element is not signed.' );
            exit;
        }
        
        /* Now we extract all available X509 certificates in the signature element. */
        $certificates = array();
        foreach ( self::mo_saml_xp_query( $signature_element, './ds:KeyInfo/ds:X509Data/ds:X509Certificate' ) as $cert_node ) {
            //phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Can not convert into Snakecase, since it is a part of DOMElement class.
            $cert_data      = trim( $cert_node->textContent );
            $cert_data      = str_replace( array( "\r", "\n", "\t", ' ' ), '', $cert_data );
            $certificates[] = $cert_data;
        }
        
        $ret = array(
            'Signature'    => $obj_xml_sec_dsig,
            'Certificates' => $certificates,
        );
        
        return $ret;
    }
    
    /**
     * Validates the signature in saml response.
     *
     * @param  array                    $info Contains the signature Data.
     * @param  Mo_SAML_XML_Security_Key $key Used to verify the signature.
     * @return void
     */
    public static function mo_saml_validate_signature( array $info, Mo_SAML_XML_Security_Key $key ) {
        $obj_xml_sec_dsig = $info['Signature'];
        
        $sig_method = self::mo_saml_xp_query( $obj_xml_sec_dsig->sig_node, './ds:SignedInfo/ds:SignatureMethod' );
        if ( empty( $sig_method ) ) {
            echo sprintf( 'Missing SignatureMethod element' );
            exit();
        }
        $sig_method = $sig_method[0];
        if ( ! $sig_method->hasAttribute( 'Algorithm' ) ) {
            echo sprintf( 'Missing Algorithm-attribute on SignatureMethod element.' );
            exit;
        }
        $algo = $sig_method->getAttribute( 'Algorithm' );
        
        if ( Mo_SAML_XML_Security_Key::RSA_SHA1 === $key->type && $algo !== $key->type ) {
            $key = self::mo_saml_cast_key( $key, $algo );
        }
        
        /* Check the signature. */
        if ( ! $obj_xml_sec_dsig->verify( $key ) ) {
            echo sprintf( 'Unable to validate Signature' );
            exit;
        }
    }
    
    /**
     * Process the SAML Response.
     *
     * @param  string           $current_url              URL or Endpoint on the SP where the IDP will redirect to with its authentication response.
     * @param  string           $cert_fingerprint         Conatains Certificate from the plugin.
     * @param  string           $signature_data           Signature Node in SAML Response.
     * @param  Mo_SAML_Response $response                 Contains SAML Response.
     * @param  string           $cert_number              Holds Cert. Number.
     * @param  string           $relay_state              an url where users will be redirected after successful authentication.
     * @return string
     */
    public static function mo_saml_process_response( $current_url, $cert_fingerprint, $signature_data, Mo_SAML_Response $response, $cert_number, $relay_state ) {
        $assertion = current( $response->mo_saml_get_assertions() );
        
        $not_before              = $assertion->mo_saml_get_not_before();
        $assertion_time_validity = get_option( 'mo_saml_assertion_time_validity' );
        
        if ( isset( $assertion_time_validity ) && 'checked' === $assertion_time_validity ) {
            self::mo_saml_verify_time_window( $assertion, $not_before );
        }
        
        /* Validate Response-element destination. */
        $msg_destination = $response->mo_saml_get_destination();
        if ( substr( $msg_destination, -1 ) === '/' ) {
            $msg_destination = substr( $msg_destination, 0, -1 );
        }
        if ( substr( $current_url, -1 ) === '/' ) {
            $current_url = substr( $current_url, 0, -1 );
        }
        
        if ( null !== $msg_destination && $msg_destination !== $current_url ) {
            Mo_SAML_Logger::mo_saml_add_log( 'Destination in response doesn\'t match the current URL. Destination is "' . esc_url( $msg_destination ) . '", current URL is "' . esc_url( $current_url ) . '".', Mo_SAML_Logger::ERROR );
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR013'];
            $error_cause   = $error_code['cause'];
            $error_message = $error_code['testConfig_msg'];
            mo_saml_display_test_config_error_page( $error_code['code'], $error_cause, $error_message );
            mo_saml_download_logs( $error_cause, $error_message );
            exit();
            
        }
        
        $response_signed = self::mo_saml_check_sign( $cert_fingerprint, $signature_data, $cert_number, $relay_state );
        
        /* Returning boolean $response_signed */
        return $response_signed;
    }
    
    
    /**
     * Checks if SAML Response is signed.
     *
     * @param  array $cert_fingerprint certificates in the SAML Response.
     * @param  array $signature_data Signature Node in SAML Response.
     * @param  int   $cert_number Holds Cert. Number.
     * @param  mixed $relay_state an url where users will be redirected after successful authentication.
     * @throws Exception Throws unable to validate signature error.
     * @return bool
     */
    public static function mo_saml_check_sign( $cert_fingerprint, $signature_data, $cert_number, $relay_state ) {
        $certificates = $signature_data['Certificates'];
        
        if ( count( $certificates ) === 0 ) {
            
            $stored_certs = maybe_unserialize( get_option( Mo_Saml_Options_Enum_Service_Provider::X509_CERTIFICATE ) );
            $pem_cert     = $stored_certs[ $cert_number ];
        } else {
            $fp_array   = array();
            $fp_array[] = $cert_fingerprint;
            $pem_cert   = self::mo_saml_find_certificate( $fp_array, $certificates, $relay_state );
            if ( false === $pem_cert ) {
                return false;
            }
        }
        
        $last_exception = null;
        
        $key = new Mo_SAML_XML_Security_Key( Mo_SAML_XML_Security_Key::RSA_SHA1, array( 'type' => 'public' ) );
        $key->mo_saml_load_key( $pem_cert );
        
        try {
            /*
             * Make sure that we have a valid signature
             */
            self::mo_saml_validate_signature( $signature_data, $key );
            return true;
        } catch ( Exception $e ) {
            $last_exception = $e;
        }
        
        /* We were unable to validate the signature with any of our keys. */
        if ( null !== $last_exception ) {
            throw $last_exception;
        } else {
            return false;
        }
        
    }
    
    
    /**
     * Validates Issuer and audience URI.
     *
     * @param  Mo_SAML_Response $saml_response Contains SAML Response.
     * @param  string           $sp_entity_id Uniquely identitify the SP.
     * @param  string           $issuer_to_validate_against SP Issuer Value.
     * @param  string           $relay_state an url where users will be redirected after successful authentication.
     * @return bool
     */
    public static function mo_saml_validate_issuer_and_audience( $saml_response, $sp_entity_id, $issuer_to_validate_against, $relay_state ) {
        $issuer    = current( $saml_response->mo_saml_get_assertions() )->mo_saml_get_issuer();
        $assertion = current( $saml_response->mo_saml_get_assertions() );
        $audiences = $assertion->mo_saml_get_valid_audiences();
        if ( strcmp( $issuer_to_validate_against, $issuer ) === 0 ) {
            if ( ! empty( $audiences ) ) {
                if ( in_array( $sp_entity_id, $audiences, true ) ) {
                    return true;
                } else {
                    
                    Mo_SAML_Logger::mo_saml_add_log(
                        Mo_Saml_Error_Log::mo_saml_write_message(
                            'UTILITIES_INVALID_AUDIENCE_URI',
                            array(
                                'spEntityId' => $sp_entity_id,
                                'audiences'  => $audiences,
                            )
                            ),
                        Mo_SAML_Logger::ERROR
                        );
                    $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR009'];
                    if ( 'testValidate' === $relay_state ) {
                        $error_cause   = $error_code['cause'];
                        $error_message = $error_code['testConfig_msg'];
                        mo_saml_display_test_config_error_page( $error_code['code'], $error_cause, $error_message );
                        mo_saml_download_logs( $error_cause, $error_message );
                        exit;
                    } else {
                        self::mo_saml_die( $error_code );
                    }
                }
            }
        } else {
            
            Mo_SAML_Logger::mo_saml_add_log(
                Mo_Saml_Error_Log::mo_saml_write_message(
                    'UTILITIES_INVALID_ISSUER',
                    array(
                        'issuerToValidateAgainst' => $issuer_to_validate_against,
                        'issuer'                  => $issuer,
                    )
                    ),
                Mo_SAML_Logger::ERROR
                );
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR010'];
            if ( 'testValidate' === $relay_state ) {
                $error_cause   = $error_code['cause'];
                $error_message = $error_code['testConfig_msg'];
                update_option( Mo_Saml_Sso_Constants::MO_SAML_REQUIRED_ISSUER, $issuer );
                mo_saml_display_test_config_error_page( $error_code['code'], $error_cause, $error_message );
                mo_saml_download_logs( $error_cause, $error_message );
                exit;
            } else {
                Mo_SAML_Utilities::mo_saml_die( $error_code );
            }
        }
    }
    
    
    
    
    
    
    
    /**
     * Checks if certificate is present or not.
     *
     * @param  array $cert_fingerprints certificates in the SAML Response.
     * @param  array $certificates certificates configured in the plugin.
     * @return string
     */
    private static function mo_saml_find_certificate( array $cert_fingerprints, array $certificates ) {
        $candidates = array();
        //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Required to decode the encoded certificates.
        $fp = strtolower( sha1( base64_decode( $certificates[0] ) ) );
        if ( ! in_array( $fp, $cert_fingerprints, true ) ) {
            $candidates[] = $fp;
            return false;
        }
        
        /* We have found a matching fingerprint. */
        $pem = "-----BEGIN CERTIFICATE-----\n" .
            chunk_split( $certificates[0], 64 ) .
            "-----END CERTIFICATE-----\n";
            
            return $pem;
            
    }
    /**
     * Santize the Certificate.
     *
     * @param  string $certificate Contains value of certificate.
     * @return string
     */
    public static function mo_saml_sanitize_certificate( $certificate ) {
        $certificate = preg_replace( "/[\r\n]+/", '', $certificate );
        $certificate = str_replace( '-', '', $certificate );
        $certificate = str_replace( 'BEGIN CERTIFICATE', '', $certificate );
        $certificate = str_replace( 'END CERTIFICATE', '', $certificate );
        $certificate = str_replace( ' ', '', $certificate );
        $certificate = chunk_split( $certificate, 64, "\r\n" );
        $certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . '-----END CERTIFICATE-----';
        return $certificate;
    }
    /**
     * Desanitize the certificate.
     *
     * @param  string $certificate Contains value of certificate.
     * @return string
     */
    public static function mo_saml_desanitize_certificate( $certificate ) {
        $certificate = preg_replace( "/[\r\n]+/", '', $certificate );
        $certificate = str_replace( '-----BEGIN CERTIFICATE-----', '', $certificate );
        $certificate = str_replace( '-----END CERTIFICATE-----', '', $certificate );
        $certificate = str_replace( ' ', '', $certificate );
        return $certificate;
    }
    
    
    
    /**
     * Return new Key with required algorithm and type, if needed.
     *
     * @param  Mo_SAML_XML_Security_Key $key Instance of MoXMLSecurityKey.
     * @param  string                   $algorithm Contains Algorithm.
     * @param  string                   $type Algorithm type.
     * @return Object
     */
    public static function mo_saml_cast_key( Mo_SAML_XML_Security_Key $key, $algorithm, $type = 'public' ) {
        // do nothing if algorithm is already the type of the key.
        if ( $key->type === $algorithm ) {
            return $key;
        }
        
        $key_info = openssl_pkey_get_details( $key->key );
        if ( false === $key_info ) {
            echo sprintf( 'Unable to get key details from XMLSecurityKey.' );
            exit;
        }
        if ( ! isset( $key_info['key'] ) ) {
            echo sprintf( 'Missing key in public key details.' );
            exit;
        }
        
        $new_key = new Mo_SAML_XML_Security_Key( $algorithm, array( 'type' => $type ) );
        $new_key->mo_saml_load_key( $key_info['key'] );
        
        return $new_key;
    }
    
    /**
     * Checks if the SAML Assertion is valid or not.
     *
     * @param  Mo_SAML_Assertion $assertion Contains SAML Assertion.
     * @param  string            $not_before It specifies the earliest time instant at which the assertion is valid.
     * @return void
     */
    public static function mo_saml_verify_time_window( $assertion, $not_before ) {
        if ( null !== $not_before && $not_before > time() + 60 ) {
            Mo_SAML_Logger::mo_saml_add_log( 'Received an assertion that is valid in the future. Check clock synchronization on IdP and SP.', Mo_SAML_Logger::ERROR );
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR007'];
            Mo_SAML_Utilities::mo_saml_die( $error_code );
        }
        
        $not_on_or_after = $assertion->mo_saml_get_not_on_or_after();
        if ( null !== $not_on_or_after && $not_on_or_after <= time() - 60 ) {
            Mo_SAML_Logger::mo_saml_add_log( 'Received an assertion that has expired. Check clock synchronization on IdP and SP.', Mo_SAML_Logger::ERROR );
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR008'];
            Mo_SAML_Utilities::mo_saml_die( $error_code );
        }
        
        $session_not_on_or_after = $assertion->mo_saml_get_session_not_on_or_after();
        if ( null !== $session_not_on_or_after && $session_not_on_or_after <= time() - 60 ) {
            Mo_SAML_Logger::mo_saml_add_log( 'Received an assertion with a session that has expired. Check clock synchronization on IdP and SP.', Mo_SAML_Logger::ERROR );
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR008'];
            Mo_SAML_Utilities::mo_saml_die( $error_code );
        }
        
    }
    
   
}