<?php
/**
 * This file is part of miniOrange SAML plugin and takes care of operations on the SAML Assertion.
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
 * @package miniorange-saml-20-single-sign-on
 */
use RobRichards\XMLSecLibs\Mo_SAML_XML_Security_Key;

if (! defined('ABSPATH')) {
    exit();
}

require_once 'class-mo-saml-utilities.php';
require_once 'class-mo-saml-assertion-handler.php';

/**
 * This class is used to operate on the SAML Assertion.
 * Takes care of operations like parsing, validation for the SAML Assertion.
 */
class Mo_SAML_Assertion
{

 
    /**
     * Identifier for the Assertion
     *
     * @var string
     */
    private $id;

    /**
     * Issue timestamp of this assertion.
     *
     * @var int
     */
    private $issue_instant;

    /**
     * Issuer of the message.
     *
     * @var string
     */
    private $issuer;

    /**
     * NameID of the Assertion.
     *
     * @var array
     */
    private $name_id;

    /**
     * Encrypted NameID
     *
     * @var mixed
     */
    private $encrypted_name_id;

    /**
     * Encrypted attribute statements in assertion.
     *
     * @var mixed
     */
    private $encrypted_attribute;

    /**
     * Key we should use to encrypt the assertion.
     *
     * @var Mo_SAML_XML_Security_Key
     */
    private $encryption_key;

    /**
     * Earliest timestamp this assertion is valid.
     *
     * @var int
     */
    private $not_before;

    /**
     * Expiration timestamp of this assertion.
     *
     * @var int
     */
    private $not_on_or_after;

    /**
     * Audiences that are allowed to receive this assertion.
     *
     * @var array
     */
    private $valid_audiences;

    /**
     * Session expiration timestamp.
     *
     * @var int
     */
    private $session_not_on_or_after;

    /**
     * Session index of the user at the IdP.
     *
     * @var string
     */
    private $session_index;

    /**
     * Timestamp the user was authenticated.
     *
     * @var int
     */
    private $authn_instant;

    /**
     * Authentication method used to authenticate the user.
     *
     * @var string
     */
    private $authn_context_class_ref;

    /**
     * Authentication context declaration.
     *
     * @var SAML2_XML_Chunk
     */
    private $authn_context_decl;

    /**
     * Authentication context declaration reference.
     *
     * @var string
     */
    private $authn_context_decl_ref;

    /**
     * AuthenticatingAuthority
     *
     * @var array
     */
    private $authenticating_authority;

    /**
     * Attributes in the Assertion
     *
     * @var array
     */
    private $attributes;

    /**
     * NameFormat used on all attributes.
     *
     * @var string
     */
    private $name_format;

    /**
     * Private key we should use to sign the assertion.
     *
     * @var Mo_SAML_XML_Security_Key
     */
    private $signature_key;

    /**
     * Certificates that should be included in the assertion.
     *
     * @var array
     */
    private $certificates;

    /**
     * Signature data for the assertion.
     *
     * @var array
     */
    private $signature_data;

    /**
     * If attributes will be sent encrypted
     *
     * @var boolean
     */
    private $required_enc_attributes;

    /**
     * SubjectConfirmation elements we have in Subject
     *
     * @var array
     */
    private $subject_confirmation;

    /**
     * If the Assertion was signed on consuruction or not.
     *
     * @var boolean
     */
    protected $was_signed_at_construction = false;

    /**
     * Constructor: Initializes Assertion Processing.
     *
     * @param DOMElement $xml
     *            Assertion in XML format.
     * @throws Exception For unsupported SAML version or for missing Issuer and ID.
     */
    private $assertion_handler;
    
    public function __construct(DOMElement $xml = null)
    {
        
        
        $this->id                       = Mo_SAML_Utilities::mo_saml_generate_id();
        $this->issue_instant            = Mo_SAML_Utilities::mo_saml_generate_time_stamp();
        $this->issuer                   = '';
        $this->authn_instant            = Mo_SAML_Utilities::mo_saml_generate_time_stamp();
        $this->attributes               = array();
        $this->name_format              = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
        $this->certificates             = array();
        $this->authenticating_authority = array();
        $this->subject_confirmation     = array();
        
        if ( null === $xml ) {
            return;
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attrbutes.
        
        if ( 'EncryptedAssertion' === $xml->localName ) {
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR001'];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This POST is recieved from the IDP side and hence will not contain nonce.
            if ( isset( $_POST['RelayState'] ) && 'testValidate' === $_POST['RelayState'] ) {
                Mo_SAML_Logger::mo_saml_add_log( 'Assertion encrypted', Mo_SAML_Logger::ERROR );
                $error_cause   = $error_code['cause'];
                $error_message = $error_code['testConfig_msg'];
                mo_saml_display_test_config_error_page( $error_code['code'], $error_cause, $error_message );
                mo_saml_download_logs( $error_cause, $error_message );
                exit;
            } else {
                Mo_SAML_Logger::mo_saml_add_log( 'Assertion encrypted', Mo_SAML_Logger::ERROR );
                Mo_SAML_Utilities::mo_saml_die( $error_code );
            }
        }
        if ( ! $xml->hasAttribute( 'ID' ) ) {
            throw new Exception( 'Missing ID attribute on SAML assertion.' );
        }
        $this->id = $xml->getAttribute( 'ID' );
        
        if ( $xml->getAttribute( 'Version' ) !== '2.0' ) {
            /* Currently a very strict check. */
            throw new Exception( 'Unsupported version: ' . $xml->getAttribute( 'Version' ) );
        }
        
        $this->issue_instant = Mo_SAML_Utilities::mo_saml_xs_date_time_to_timestamp( $xml->getAttribute( 'IssueInstant' ) );
        
        $issuer = Mo_SAML_SSO_Utilities::mo_saml_xp_query( $xml, './saml_assertion:Issuer' );
        if ( empty( $issuer ) ) {
            throw new Exception( 'Missing <saml:Issuer> in assertion.' );
        }
        $this->issuer = trim( $issuer[0]->textContent );
        $this->assertion_handler=Mo_SAML_Assertion_Handler::getInstance($this,$xml);
        
    }
          
    /**
     * Validate this assertion against a public key.
     *
     * If no signature was present on the assertion, we will return FALSE.
     * Otherwise, TRUE will be returned. An exception is thrown if the
     * signature validation fails.
     *
     * @param Mo_SAML_XML_Security_Key $key
     *            The key we should check against.
     * @return boolean TRUE if successful, FALSE if it is unsigned.
     */
    /**
     * Retrieve the identifier of this assertion.
     *
     * @return string The identifier of this assertion.
     */
   
    /**
     * Set the identifier of this assertion.
     *
     * @param string $id
     *            The new identifier of this assertion.
     */
    public function mo_saml_set_id($id)
    {
        $this->id = $id;
    }

    /**
     * Retrieve the issue timestamp of this assertion.
     *
     * @return int The issue timestamp of this assertion, as an UNIX timestamp.
     */
    public function mo_saml_get_issue_instant()
    {
        
        return $this->issue_instant;
    
    }

    /**
     * Set the issue timestamp of this assertion.
     *
     * @param int $issue_instant
     *            The new issue timestamp of this assertion, as an UNIX timestamp.
     */
    public function mo_saml_set_issue_instant($issue_instant)
    {
        $this->issue_instant = $issue_instant;
    }

    /**
     * Retrieve the issuer if this assertion.
     *
     * @return string The issuer of this assertion.
     */
    public function mo_saml_get_issuer()
    {
        return $this->issuer;
    }

    /**
     * Set the issuer of this message.
     *
     * @param string $issuer
     *            The new issuer of this assertion.
     */
    public function mo_saml_set_issuer($issuer)
    {
        $this->issuer = $issuer;
    }

    /**
     * Retrieve the NameId of the subject in the assertion.
     *
     * The returned NameId is in the format used by Mo_SAML_Utilities::addNameId().
     *
     * @see Mo_SAML_Utilities::addNameId()
     * @return array|NULL The name identifier of the assertion.
     * @throws Exception If the nameID is encrypted and is retrived directly.
     */
    public function mo_saml_get_name_id()
    {
        if (null !== $this->encrypted_name_id) {
            throw new Exception('Attempted to retrieve encrypted NameID without decrypting it first.');
        }

        return $this->name_id;
    }

    /**
     * Set the NameId of the subject in the assertion.
     *
     * The NameId must be in the format accepted by Mo_SAML_Utilities::addNameId().
     *
     * @see Mo_SAML_Utilities::addNameId()
     * @param array|NULL $name_id
     *            The name identifier of the assertion.
     */
    public function mo_saml_set_name_id($name_id)
    {
        $this->name_id = $name_id;
    }

    /**
     * Retrieve the NameId of the subject in the assertion.
     *
     * The returned NameId is in the format used by Mo_SAML_Utilities::addNameId().
     *
     * @see Mo_SAML_Utilities::addNameId()
     * @return array|NULL The name identifier of the assertion.
     * @throws Exception If the nameID is encrypted and is retrived directly.
     */
    public function mo_saml_get_encrypted_name_id()
    {
        return $this->encrypted_name_id;
    }

    /**
     * Set the NameId of the subject in the assertion.
     *
     * The NameId must be in the format accepted by Mo_SAML_Utilities::addNameId().
     *
     * @see Mo_SAML_Utilities::addNameId()
     * @param array|NULL $name_id
     *            The name identifier of the assertion.
     */
    public function mo_saml_set_encrypted_name_id($encrypted_name_id)
    {
        $this->encrypted_name_id = $encrypted_name_id;
    }

    /**
     * Check whether the NameId is encrypted.
     *
     * @return TRUE if the NameId is encrypted, FALSE if not.
     */
    public function mo_saml_is_name_id_encrypted()
    {
        if (null !== $this->encrypted_name_id) {
            return true;
        }

        return false;
    }

    /**
     * Retrieve the earliest timestamp this assertion is valid.
     *
     * This function returns NULL if there are no restrictions on how early the
     * assertion can be used.
     *
     * @return int|NULL The earliest timestamp this assertion is valid.
     */
    public function mo_saml_get_not_before()
    {
        return $this->not_before;
    }

    /**
     * Set the earliest timestamp this assertion can be used.
     *
     * Set this to NULL if no limit is required.
     *
     * @param int|NULL $not_before
     *            The earliest timestamp this assertion is valid.
     */
    public function mo_saml_set_not_before($not_before)
    {
        $this->not_before = $not_before;
    }

    /**
     * Retrieve the expiration timestamp of this assertion.
     *
     * This function returns NULL if there are no restrictions on how
     * late the assertion can be used.
     *
     * @return int|NULL The latest timestamp this assertion is valid.
     */
    public function mo_saml_get_not_on_or_after()
    {
        return $this->not_on_or_after;
    }

    /**
     * Set the expiration timestamp of this assertion.
     *
     * Set this to NULL if no limit is required.
     *
     * @param int|NULL $not_on_or_after
     *            The latest timestamp this assertion is valid.
     */
    public function mo_saml_set_not_on_or_after($not_on_or_after)
    {
        $this->not_on_or_after = $not_on_or_after;
    }

    /**
     * Set $EncryptedAttributes if attributes will send encrypted
     *
     * @param boolean $ea
     *            TRUE to encrypt attributes in the assertion.
     */
    public function mo_saml_set_encrypted_attributes($ea)
    {
        $this->required_enc_attributes = $ea;
    }
    /**
     * Set $EncryptedAttributes if attributes will send encrypted
     *
     * @param boolean $ea
     *            TRUE to encrypt attributes in the assertion.
     */
    public function mo_saml_get_encrypted_attributes()
    {
       return $this->required_enc_attributes;
    }
    
    public function mo_saml_set_encrypted_attribute($ea)
    {
        $this->encrypted_attribute=$ea;
    }

    /**
     * Retrieve the audiences that are allowed to receive this assertion.
     *
     * This may be NULL, in which case all audiences are allowed.
     *
     * @return array|NULL The allowed audiences.
     */
    public function mo_saml_get_valid_audiences()
    {
        return $this->valid_audiences;
    }

    /**
     * Set the audiences that are allowed to receive this assertion.
     *
     * This may be NULL, in which case all audiences are allowed.
     *
     * @param array|NULL $valid_audiences
     *            The allowed audiences.
     */
    public function mo_saml_set_valid_audiences(array $valid_audiences = null)
    {
        $this->valid_audiences = $valid_audiences;
    }

    /**
     * Retrieve the AuthnInstant of the assertion.
     *
     * @return int|NULL The timestamp the user was authenticated, or NULL if the user isn't authenticated.
     */
    public function mo_saml_get_authn_instant()
    {
        return $this->authn_instant;
    }

    /**
     * Set the AuthnInstant of the assertion.
     *
     * @param int|NULL $authn_instant
     *            Timestamp the user was authenticated, or NULL if we don't want an AuthnStatement.
     */
    public function mo_saml_set_authn_instant($authn_instant)
    {
        $this->authn_instant = $authn_instant;
    }

    /**
     * Retrieve the session expiration timestamp.
     *
     * This function returns NULL if there are no restrictions on the
     * session lifetime.
     *
     * @return int|NULL The latest timestamp this session is valid.
     */
    public function mo_saml_get_session_not_on_or_after()
    {
        return $this->session_not_on_or_after;
    }

    /**
     * Set the session expiration timestamp.
     *
     * Set this to NULL if no limit is required.
     *
     * @param int|NULL $session_not_on_or_after
     *            The latest timestamp this session is valid.
     */
    public function mo_saml_set_session_not_on_or_after($session_not_on_or_after)
    {
        $this->session_not_on_or_after = $session_not_on_or_after;
    }

    /**
     * Retrieve the session index of the user at the IdP.
     *
     * @return string|NULL The session index of the user at the IdP.
     */
    public function mo_saml_get_session_index()
    {
        return $this->session_index;
    }

    /**
     * Set the session index of the user at the IdP.
     *
     * Note that the authentication context must be set before the
     * session index can be inluded in the assertion.
     *
     * @param string|NULL $session_index
     *            The session index of the user at the IdP.
     */
    public function mo_saml_set_session_index($session_index)
    {
        $this->session_index = $session_index;
    }

    /**
     * Retrieve the authentication method used to authenticate the user.
     *
     * This will return NULL if no authentication statement was
     * included in the assertion.
     *
     * Note that this returns either the AuthnContextClassRef or the AuthnConextDeclRef, whose definition overlaps
     * but is slightly different (consult the specification for more information).
     * This was done to work around an old bug of Shibboleth ( https://bugs.internet2.edu/jira/browse/SIDP-187 ).
     * Should no longer be required, please use either getAuthnConextClassRef or getAuthnContextDeclRef.
     *
     * @deprecated use getAuthnContextClassRef
     * @return string|NULL The authentication method.
     */
    public function mo_saml_get_authn_context()
    {
        if (! empty($this->authn_context_class_ref)) {
            return $this->authn_context_class_ref;
        }
        if (! empty($this->authn_context_decl_ref)) {
            return $this->authn_context_decl_ref;
        }
        return null;
    }

    /**
     * Set the authentication method used to authenticate the user.
     *
     * If this is set to NULL, no authentication statement will be
     * included in the assertion. The default is NULL.
     *
     * @deprecated use mo_saml_set_authn_context_class_ref
     * @param string|NULL $authn_context
     *            The authentication method.
     */
    public function mo_saml_set_authn_context($authn_context)
    {
        $this->mo_saml_set_authn_context_class_ref($authn_context);
    }

    /**
     * Retrieve the authentication method used to authenticate the user.
     *
     * This will return NULL if no authentication statement was
     * included in the assertion.
     *
     * @return string|NULL The authentication method.
     */
    public function mo_saml_get_authn_context_class_ref()
    {
        return $this->authn_context_class_ref;
    }

    /**
     * Set the authentication method used to authenticate the user.
     *
     * If this is set to NULL, no authentication statement will be
     * included in the assertion. The default is NULL.
     *
     * @param string|NULL $authn_context_class_ref
     *            The authentication method.
     */
    public function mo_saml_set_authn_context_class_ref($authn_context_class_ref)
    {
        $this->authn_context_class_ref = $authn_context_class_ref;
    }

    /**
     * Set the authentication context declaration.
     *
     * @param \SAML2_XML_Chunk $authn_context_decl
     *            SAML2 XML chunk.
     * @throws Exception If the AuthnContextDeclRef is already registered.
     */
    public function mo_saml_set_authn_context_decl(SAML2_XML_Chunk $authn_context_decl)
    {
        if (! empty($this->authn_context_decl_ref)) {
            throw new Exception('AuthnContextDeclRef is already registered! May only have either a Decl or a DeclRef, not both!');
        }

        $this->authn_context_decl = $authn_context_decl;
    }

    /**
     * Get the authentication context declaration.
     *
     * See:
     *
     * @url http://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
     *
     * @return \SAML2_XML_Chunk|NULL
     */
    public function mo_saml_get_authn_aontext_aecl()
    {
        return $this->authn_context_decl;
    }

    /**
     * Set the authentication context declaration reference.
     *
     * @param string $authn_context_decl_ref
     *            The Authentication Context Declaration Reference.
     * @throws Exception If AuthnContextDecl is already registered.
     */
    public function mo_saml_set_authn_context_decl_ref($authn_context_decl_ref)
    {

        if (! empty($this->authn_context_decl)) {
            throw new Exception('AuthnContextDecl is already registered! May only have either a Decl or a DeclRef, not both!');
        }

        $this->authn_context_decl_ref = $authn_context_decl_ref;
    }

    /**
     * Get the authentication context declaration reference.
     * URI reference that identifies an authentication context declaration.
     *
     * The URI reference MAY directly resolve into an XML document containing the referenced declaration.
     *
     * @return string
     */
    public function mo_saml_get_authn_context_decl_ref()
    {
        return $this->authn_context_decl_ref;
    }

    /**
     * Retrieve the AuthenticatingAuthority.
     *
     * @return array
     */
    public function mo_saml_get_authenticating_authority()
    {
        return $this->authenticating_authority;
    }

    /**
     * Set the AuthenticatingAuthority
     *
     * @param array $authenticating_authority
     *            Authentication Authority.
     */
    public function mo_saml_set_authenticating_authority($authenticating_authority)
    {
        $this->authenticating_authority = $authenticating_authority;
    }

    /**
     * Retrieve all attributes.
     *
     * @return array All attributes, as an associative array.
     */
    public function mo_saml_get_attributes()
    {
        return $this->attributes;
    }

    /**
     * Replace all attributes.
     *
     * @param array $attributes
     *            All new attributes, as an associative array.
     */
    public function mo_saml_set_attributes(array $attributes)
    {
        $this->attributes = $attributes;
    }

    /**
     * Retrieve the NameFormat used on all attributes.
     *
     * If more than one NameFormat is used in the received attributes, this
     * returns the unspecified NameFormat.
     *
     * @return string The NameFormat used on all attributes.
     */
    public function mo_saml_get_attribute_name_format()
    {
        return $this->name_format;
    }

    /**
     * Set the NameFormat used on all attributes.
     *
     * @param string $name_format
     *            The NameFormat used on all attributes.
     */
    public function set_attribute_name_format($name_format)
    {
        $this->name_format = $name_format;
    }

    /**
     * Retrieve the SubjectConfirmation elements we have in our Subject element.
     *
     * @return array Array of SAML2_XML_saml_SubjectConfirmation elements.
     */
    public function mo_saml_get_subject_confirmation()
    {
        return $this->subject_confirmation;
    }

    /**
     * Set the SubjectConfirmation elements that should be included in the assertion.
     *
     * @param array $subject_confirmation
     *            Array of SAML2_XML_saml_SubjectConfirmation elements.
     */
    public function mo_saml_set_subject_confirmation(array $subject_confirmation)
    {
        $this->subject_confirmation = $subject_confirmation;
    }

    /**
     * Retrieve the private key we should use to sign the assertion.
     *
     * @return Mo_SAML_XML_Security_Key|NULL The key, or NULL if no key is specified.
     */
    public function mo_saml_get_signature_key()
    {
        return $this->signature_key;
    }

    /**
     * Set the private key we should use to sign the assertion.
     *
     * If the key is NULL, the assertion will be sent unsigned.
     *
     * @param Mo_SAML_XML_Security_Key|NULL $signature_key
     *            Default value NULL.
     */
    public function mo_saml_set_signature_key(XMLsecurityKey $signature_key = null)
    {
        $this->signature_key = $signature_key;
    }

    /**
     * Return the key we should use to encrypt the assertion.
     *
     * @return Mo_SAML_XML_Security_Key|NULL The key, or NULL if no key is specified..
     */
    public function mo_saml_get_encryption_key()
    {
        return $this->encryption_key;
    }

    /**
     * Set the private key we should use to encrypt the attributes.
     *
     * @param Mo_SAML_XML_Security_Key|NULL $key
     *            Default value NULL.
     */
    public function mo_saml_set_encryption_key(Mo_SAML_XML_Security_Key $key = null)
    {
        $this->encryption_key = $key;
    }

    /**
     * Set the certificates that should be included in the assertion.
     *
     * The certificates should be strings with the PEM encoded data.
     *
     * @param array $certificates
     *            An array of certificates.
     */
    public function mo_saml_set_certificates(array $certificates)
    {
        $this->certificates = $certificates;
    }

    /**
     * Retrieve the certificates that are included in the assertion.
     *
     * @return array An array of certificates.
     */
    public function mo_saml_get_certificates()
    {
        return $this->certificates;
    }

    /**
     * Retrives signature data for the assertion.
     *
     * @return array
     */
    public function mo_saml_get_signature_data()
    {
        return $this->signature_data;
    }
    /**
     * Retrives signature data for the assertion.
     *
     * @return array
     */
    public function mo_saml_set_signature_data($sd)
    {
        $this->signature_data=$sd;
    }
    
    
    /**
     * Returns if the Assertion was signed on consuruction or not.
     *
     * @return bool
     */
    public function mo_saml_get_was_signed_at_construction()
    {
        return $this->was_signed_at_construction;
    }
    /**
     * Set the was signed at construction*/
    public function mo_saml_set_was_signed_at_construction($was_signed)
    {
        $this->was_signed_at_construction = $was_signed;
    }
}
