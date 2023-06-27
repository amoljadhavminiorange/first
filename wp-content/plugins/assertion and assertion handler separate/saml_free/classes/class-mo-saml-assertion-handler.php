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
/**
 * This class is used to operate on the SAML Assertion.
 * Takes care of operations like parsing, validation for the SAML Assertion.
 */


class Mo_SAML_Assertion_Handler
{
    private $assertion_handler;
    
    /**
     * Constructor: Initializes Assertion Processing.
     *
     * @param DOMElement $xml
     *            Assertion in XML format.
     * @throws Exception For unsupported SAML version or for missing Issuer and ID.
     */
    public function __construct(DOMElement $xml = null)
    {
        
        $this->assertion_handler=Mo_SAML_Assertion::getInstance();
        if (null === $xml) {
            return;
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attrbutes.
        if ('EncryptedAssertion' === $xml->localName) {
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR001'];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This POST is recieved from the IDP side and hence will not contain nonce.
            if (isset($_POST['RelayState']) && 'testValidate' === $_POST['RelayState']) {
                Mo_SAML_Logger::mo_saml_add_log('Assertion encrypted', Mo_SAML_Logger::ERROR);
                $error_cause = $error_code['cause'];
                $error_message = $error_code['testConfig_msg'];
                mo_saml_display_test_config_error_page($error_code['code'], $error_cause, $error_message);
                mo_saml_download_logs($error_cause, $error_message);
                exit();
            } else {
                Mo_SAML_Logger::mo_saml_add_log('Assertion encrypted', Mo_SAML_Logger::ERROR);
                Mo_SAML_Utilities::mo_saml_die($error_code);
            }
        }
        if (! $xml->hasAttribute('ID')) {
            throw new Exception('Missing ID attribute on SAML assertion.');
        }
        $this->assertion_handler->mo_saml_set_id($xml->getAttribute('ID'));
        
        if ($xml->getAttribute('Version') !== '2.0') {
            /* Currently a very strict check. */
            throw new Exception('Unsupported version: ' . $xml->getAttribute('Version'));
        }
        
        $this->assertion_handler->mo_saml_set_issue_instant(Mo_SAML_Utilities::mo_saml_xs_date_time_to_timestamp($xml->getAttribute('IssueInstant')));
        
        $issuer = Mo_SAML_SSO_Utilities::mo_saml_xp_query($xml, './saml_assertion:Issuer');
        if (empty($issuer)) {
            throw new Exception('Missing <saml:Issuer> in assertion.');
        }
        $this->assertion_handler->mo_saml_set_issuer(trim($issuer[0]->textContent));
        $this->mo_saml_parse_conditions( $xml );
        $this->mo_saml_parse_authn_statement( $xml );
        $this->mo_saml_parse_attributes( $xml );
        $this->mo_saml_parse_encrypted_attributes( $xml );
        $this->mo_saml_parse_signature( $xml );
        $this->mo_saml_parse_subject( $xml );
    }

    /**
     * Parse subject in assertion.
     *
     * @param DOMElement $xml
     *            The assertion XML element.
     * @throws Exception For more than one nodes of the following: Subject, NameID, EncryptedData.
     */
    
    private function mo_saml_parse_subject(DOMElement $xml)
    {   $subject = Mo_SAML_SSO_Utilities::mo_saml_xp_query($xml, './saml_assertion:Subject');
        if (empty($subject)) {
            /* No Subject node. */
            
            return;
        } elseif (count($subject) > 1) {
            throw new Exception('More than one <saml:Subject> in <saml:Assertion>.');
        }
        
        $subject = $subject[0];
        
        $name_id = Mo_SAML_SSO_Utilities::mo_saml_xp_query($subject, './saml_assertion:NameID | ./saml_assertion:EncryptedID/xenc:EncryptedData');
        if (empty($name_id)) {
            $error_code = Mo_Saml_Options_Enum_Error_Codes::$error_codes['WPSAMLERR002'];
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This POST is recieved from the IDP side and hence will not contain nonce.
            if (isset($_POST['RelayState']) && 'testValidate' === $_POST['RelayState']) {
                $error_cause = $error_code['cause'];
                $error_message = $error_code['testConfig_msg'];
                mo_saml_display_test_config_error_page($error_code['code'], $error_cause, $error_message);
                mo_saml_download_logs($error_cause, $error_message);
            } else {
                Mo_SAML_Utilities::mo_saml_die($error_code);
            }
        } elseif (count($name_id) > 1) {
            throw new Exception('More than one <saml:NameID> or <saml:EncryptedData> in <saml:Subject>.');
        }
        $name_id = $name_id[0];
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
        if ('EncryptedData' === $name_id->localName) {
            /* The NameID element is encrypted. */
            $this->assertion_handler->mo_saml_set_encrypted_name_id($name_id);
        } else {
            //   $this->name_id = Mo_SAML_Utilities::mo_saml_parse_name_id($name_id);
            $this->assertion_handler->mo_saml_set_name_id(Mo_SAML_Utilities::mo_saml_parse_name_id($name_id));
        }
    }
    
    /**
     * Parse conditions in assertion.
     *
     * @param DOMElement $xml
     *            The assertion XML element.
     * @throws Exception For more than one conditions nodes in SAML Assertion or for unknown conditions.
     */
    private function mo_saml_parse_conditions(DOMElement $xml)
    {
        $conditions = Mo_SAML_SSO_Utilities::mo_saml_xp_query($xml, './saml_assertion:Conditions');
        if (empty($conditions)) {
            /* No <saml:Conditions> node. */
            
            return;
        } elseif (count($conditions) > 1) {
            throw new Exception('More than one <saml:Conditions> in <saml:Assertion>.');
        }
        $conditions = $conditions[0];
        
        if ($conditions->hasAttribute('NotBefore')) {
            $not_before = Mo_SAML_Utilities::mo_saml_xs_date_time_to_timestamp($conditions->getAttribute('NotBefore'));
            if (null === $this->assertion_handler->mo_saml_get_not_before() || $this->assertion_handler->mo_saml_get_not_before() < $not_before) {
                $this->assertion_handler->mo_saml_set_not_before($not_before);
            }
        }
        if ($conditions->hasAttribute('NotOnOrAfter')) {
            $not_on_or_after = Mo_SAML_Utilities::mo_saml_xs_date_time_to_timestamp($conditions->getAttribute('NotOnOrAfter'));
            if (null === $this->assertion_handler->mo_saml_get_not_on_or_after() || $this->assertion_handler->mo_saml_get_not_on_or_after() > $not_on_or_after) {
                $this->assertion_handler->mo_saml_set_not_on_or_after($not_on_or_after);
            }
            
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
        for ($node = $conditions->firstChild; null !== $node; $node = $node->nextSibling) {
            if ($node instanceof DOMText) {
                continue;
            }
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
            if ('urn:oasis:names:tc:SAML:2.0:assertion' !== $node->namespaceURI) {
                // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase, WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Ignoring camel case for DOMElement attribute, var_export is used to print useful information while throwing exceptions.
                throw new Exception('Unknown namespace of condition: ' . var_export($node->namespaceURI, true));
            }
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
            switch ($node->localName) {
                case 'AudienceRestriction':
                    $audiences = Mo_SAML_SSO_Utilities::mo_saml_extract_strings($node, 'urn:oasis:names:tc:SAML:2.0:assertion', 'Audience');
                    if (null === $this->assertion_handler->mo_saml_get_valid_audiences()) {
                        /* The first (and probably last) AudienceRestriction element. */
                        $this->assertion_handler->mo_saml_set_valid_audiences($audiences);
                    } else {
                        /*
                         * The set of AudienceRestriction are ANDed together, so we need
                         * the subset that are present in all of them.
                         */
                        $this->assertion_handler->mo_saml_set_valid_audiences(array_intersect($this->assertion_handler->mo_saml_get_valid_audiences(), $audiences));
                    }
                    break;
                case 'OneTimeUse':
                    /* Currently ignored. */
                    break;
                case 'ProxyRestriction':
                    /* Currently ignored. */
                    break;
                default:
                    // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase, WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Ignoring camel case for DOMElement attribute, var_export is used to print useful information while throwing exceptions.
                    throw new Exception('Unknown condition: ' . var_export($node->localName, true));
            }
        }
    }
    
    /**
     * Parse AuthnStatement in assertion.
     *
     * @param DOMElement $xml
     *            The assertion XML element.
     * @throws Exception For multiple AuthnStatement nodes and for missing AuthnInstant.
     */
    private function mo_saml_parse_authn_statement(DOMElement $xml)
    {
        $authn_statements = Mo_SAML_SSO_Utilities::mo_saml_xp_query($xml, './saml_assertion:AuthnStatement');
        if (empty($authn_statements)) {
            $this->assertion_handler->mo_saml_set_authn_instant(null);
            
            return;
        } elseif (count($authn_statements) > 1) {
            throw new Exception('More that one <saml:AuthnStatement> in <saml:Assertion> not supported.');
        }
        $authn_statement = $authn_statements[0];
        
        if (! $authn_statement->hasAttribute('AuthnInstant')) {
            throw new Exception('Missing required AuthnInstant attribute on <saml:AuthnStatement>.');
        }
        $this->assertion_handler->mo_saml_set_authn_instant(Mo_SAML_Utilities::mo_saml_xs_date_time_to_timestamp($authn_statement->getAttribute('AuthnInstant')));
        
        if ($authn_statement->hasAttribute('SessionNotOnOrAfter')) {
            $this->assertion_handler->mo_saml_set_session_not_on_or_after(Mo_SAML_Utilities::mo_saml_xs_date_time_to_timestamp($authn_statement->getAttribute('SessionNotOnOrAfter')));
        }
        
        if ($authn_statement->hasAttribute('SessionIndex')) {
            $this->assertion_handler->mo_saml_set_session_index($authn_statement->getAttribute('SessionIndex'));
        }
        
        $this->mo_saml_parse_authn_context($authn_statement);
    }
    
    /**
     * Parse AuthnContext in AuthnStatement.
     *
     * @param DOMElement $authn_statement_el
     *            XML element for AuthenStatement.
     * @throws Exception For invalid or missing Authentication Context.
     */
    private function mo_saml_parse_authn_context(DOMElement $authn_statement_el)
    {
        // Get the AuthnContext element.
        $authn_contexts = Mo_SAML_SSO_Utilities::mo_saml_xp_query($authn_statement_el, './saml_assertion:AuthnContext');
        if (count($authn_contexts) > 1) {
            throw new Exception('More than one <saml:AuthnContext> in <saml:AuthnStatement>.');
        } elseif (empty($authn_contexts)) {
            throw new Exception('Missing required <saml:AuthnContext> in <saml:AuthnStatement>.');
        }
        $authn_context_el = $authn_contexts[0];
        
        // Get the AuthnContextDeclRef (if available).
        $authn_context_decl_refs = Mo_SAML_SSO_Utilities::mo_saml_xp_query($authn_context_el, './saml_assertion:AuthnContextDeclRef');
        if (count($authn_context_decl_refs) > 1) {
            throw new Exception('More than one <saml:AuthnContextDeclRef> found?');
        } elseif (count($authn_context_decl_refs) === 1) {
            $this->assertion_handler->mo_saml_set_authn_context_decl_ref(trim($authn_context_decl_refs[0]->textContent));
        }
        
        // Get the AuthnContextDecl (if available).
        $authn_context_decls = Mo_SAML_SSO_Utilities::mo_saml_xp_query($authn_context_el, './saml_assertion:AuthnContextDecl');
        if (count($authn_context_decls) > 1) {
            throw new Exception('More than one <saml:AuthnContextDecl> found?');
        } elseif (count($authn_context_decls) === 1) {
            $this->assertion_handler->mo_saml_set_authn_context_decl(new SAML2_XML_Chunk($authn_context_decls[0]));
        }
        
        // Get the AuthnContextClassRef (if available).
        $authn_context_class_refs = Mo_SAML_SSO_Utilities::mo_saml_xp_query($authn_context_el, './saml_assertion:AuthnContextClassRef');
        if (count($authn_context_class_refs) > 1) {
            throw new Exception('More than one <saml:AuthnContextClassRef> in <saml:AuthnContext>.');
        } elseif (count($authn_context_class_refs) === 1) {
            $this->assertion_handler->mo_saml_set_authn_context_class_ref(trim($authn_context_class_refs[0]->textContent));
        }
        
        // Constraint from XSD: MUST have one of the three.
        if (empty($this->assertion_handler->mo_saml_get_authn_context()) && empty($this->assertion_handler->mo_saml_get_authn_aontext_aecl()) && empty($this->assertion_handler->mo_saml_get_authn_context_decl_ref())) {
            throw new Exception('Missing either <saml:AuthnContextClassRef> or <saml:AuthnContextDeclRef> or <saml:AuthnContextDecl>');
        }
        
        $this->assertion_handler->mo_saml_set_authenticating_authority(Mo_SAML_SSO_Utilities::mo_saml_extract_strings($authn_context_el, 'urn:oasis:names:tc:SAML:2.0:assertion', 'AuthenticatingAuthority'));
    }
    
    /**
     * Parse attribute statements in assertion.
     *
     * @param DOMElement $xml
     *            The XML element with the assertion.
     * @throws Exception For missing name on SAML Attribute.
     */
    private function mo_saml_parse_attributes(DOMElement $xml)
    {
        $first_attribute = true;
        $attributes = Mo_SAML_SSO_Utilities::mo_saml_xp_query($xml, './saml_assertion:AttributeStatement/saml_assertion:Attribute');
        foreach ($attributes as $attribute) {
            if (! $attribute->hasAttribute('Name')) {
                throw new Exception('Missing name on <saml:Attribute> element.');
            }
            $name = $attribute->getAttribute('Name');
            
            if ($attribute->hasAttribute('NameFormat')) {
                $name_format = $attribute->getAttribute('NameFormat');
            } else {
                $name_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
            }
            
            if ($first_attribute) {
               
                $this->assertion_handler->set_attribute_name_format($name_format);
                $first_attribute = false;
            } else {
                if ($this->assertion_handler->mo_saml_get_attribute_name_format() !== $name_format) {
                    $this->assertion_handler->set_attribute_name_format('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
                }
            }
            $instance_attributes=$this->assertion_handler->mo_saml_get_attributes();
            if (empty($instance_attributes[$name])) {
                $instance_attributes= array();
            }
            
            $values = Mo_SAML_SSO_Utilities::mo_saml_xp_query($attribute, './saml_assertion:AttributeValue');
            foreach ($values as $value) {
                // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMNode Attributes
                $instance_attributes[$name][] = trim($value->textContent);
            }
        }
    }
    
    /**
     * Parse encrypted attribute statements in assertion.
     *
     * @param DOMElement $xml
     *            The XML element with the assertion.
     */
    private function mo_saml_parse_encrypted_attributes(DOMElement $xml)
    {
        $this->assertion_handler->mo_saml_set_encrypted_attribute(Mo_SAML_SSO_Utilities::mo_saml_xp_query($xml, './saml_assertion:AttributeStatement/saml_assertion:EncryptedAttribute'));
    }
    
    /**
     * Parse signature on assertion.
     *
     * @param DOMElement $xml
     *            The assertion XML element.
     */
    private function mo_saml_parse_signature(DOMElement $xml)
    {
        /* Validate the signature element of the message. */
        $sig = Mo_SAML_SSO_Utilities::mo_saml_validate_element($xml);
        if (false !== $sig) {
            $this->assertion_handler->mo_saml_set_was_signed_at_construction(true);
            $this->assertion_handler->mo_saml_set_certificates($sig['Certificates']);
            $this->assertion_handler->mo_saml_set_signature_data($sig);
        }
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
    public function mo_saml_validate(Mo_SAML_XML_Security_Key $key)
    {
        if (null === $this->assertion_handler->mo_saml_get_signature_data()) {
            return false;
        }
        
        Mo_SAML_SSO_Utilities::mo_saml_validate_signature($this->assertion_handler->mo_saml_get_signature_data(), $key);
        
        return true;
    }
    
    /**
     * Encrypt the NameID in the Assertion.
     *
     * @param Mo_SAML_XML_Security_Key $key
     *            The encryption key.
     */
    public function mo_saml_encrypt_name_id(Mo_SAML_XML_Security_Key $key)
    {
        /* First create a XML representation of the NameID. */
        $doc = new DOMDocument();
        $root = $doc->createElement('root');
        $doc->appendChild($root);
        Mo_SAML_Utilities::addNameId($root, $this->assertion_handler->mo_saml_get_name_id());
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes
        $name_id = $root->firstChild;
        
        Mo_SAML_Utilities::getContainer()->debugMessage($name_id, 'encrypt');
        
        /* Encrypt the NameID. */
        $enc = new XMLSecEnc();
        $enc->setNode($name_id);
        // @codingStandardsIgnoreStart
        $enc->type = XMLSecEnc::Element;
        // @codingStandardsIgnoreEnd
        
        $symmetric_key = new Mo_SAML_XML_Security_Key(Mo_SAML_XML_Security_Key::AES128_CBC);
        $symmetric_key->mo_saml_generate_session_key();
        $enc->encryptKey($key, $symmetric_key);
        
        $this->assertion_handler->mo_saml_set_encrypted_name_id($enc->encryptNode($symmetric_key));
        $this->assertion_handler->mo_saml_set_name_id(null);
    }
    
    /**
     * Convert this assertion to an XML element.
     *
     * @param DOMNode|NULL $parent_element
     *            The DOM node the assertion should be created in.
     * @return DOMElement This assertion.
     */
    public function mo_saml_to_xml(DOMNode $parent_element = null)
    {
        if (null === $parent_element) {
            $document = new DOMDocument();
            $parent_element = $document;
        } else {
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
            $document = $parent_element->ownerDocument;
        }
        
        $root = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Assertion');
        $parent_element->appendChild($root);
        
        /* Ugly hack to add another namespace declaration to the root element. */
        $root->setAttributeNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:tmp', 'tmp');
        $root->removeAttributeNS('urn:oasis:names:tc:SAML:2.0:protocol', 'tmp');
        $root->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:tmp', 'tmp');
        $root->removeAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'tmp');
        $root->setAttributeNS('http://www.w3.org/2001/XMLSchema', 'xs:tmp', 'tmp');
        $root->removeAttributeNS('http://www.w3.org/2001/XMLSchema', 'tmp');
        
        $root->setAttribute('ID', Mo_SAML_Utilities::mo_saml_generate_id());
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->assertion_handler->mo_saml_get_issue_instant()));
        
        $issuer = Mo_SAML_Utilities::addString($root, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $this->assertion_handler->mo_saml_get_issuer());
        
        $this->mo_saml_add_subject($root);
        $this->mo_saml_add_conditions($root);
        $this->mo_saml_add_authn_statement($root);
        if (false === $this->assertion_handler->mo_saml_get_encrypted_attributes()) {
            $this->mo_saml_add_attribute_statement($root);
        } else {
            $this->mo_saml_add_encrypted_attribute_statement($root);
        }
        
        if (null !== $this->assertion_handler->mo_saml_get_signature_key()) {
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
            Mo_SAML_Utilities::insertSignature($this->assertion_handler->mo_saml_get_signature_key(), $this->assertion_handler->mo_saml_get_certificates(), $root, $issuer->nextSibling);
        }
        
        return $root;
    }
    
    /**
     * Add a Subject-node to the assertion.
     *
     * @param DOMElement $root
     *            The assertion element we should add the subject to.
     */
    private function mo_saml_add_subject(DOMElement $root)
    {
        if (null === $this->assertion_handler->mo_saml_get_name_id() && null === $this->assertion_handler->mo_saml_get_encrypted_name_id()) {
            /* We don't have anything to create a Subject node for. */
            
            return;
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
        $subject = $root->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Subject');
        $root->appendChild($subject);
        
        if (null === $this->assertion_handler->mo_saml_get_encrypted_name_id()) {
            Mo_SAML_Utilities::addNameId($subject, $this->assertion_handler->mo_saml_get_name_id());
        } else {
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
            $eid = $subject->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:EncryptedID');
            $subject->appendChild($eid);
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
            $eid->appendChild($subject->ownerDocument->importNode($this->assertion_handler->mo_saml_get_encrypted_name_id(), true));
        }
        
        foreach ($this->assertion_handler->mo_saml_get_subject_confirmation() as $sc) {
            $sc->mo_saml_to_xml($subject);
        }
    }
    
    /**
     * Add a Conditions-node to the assertion.
     *
     * @param DOMElement $root
     *            The assertion element we should add the conditions to.
     */
    private function mo_saml_add_conditions(DOMElement $root)
    {
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
        $document = $root->ownerDocument;
        
        $conditions = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Conditions');
        $root->appendChild($conditions);
        
        if (null !== $this->assertion_handler->mo_saml_get_not_before()) {
            $conditions->setAttribute('NotBefore', gmdate('Y-m-d\TH:i:s\Z', $this->assertion_handler->mo_saml_get_not_before()));
        }
        if (null !== $this->assertion_handler->mo_saml_get_not_on_or_after()) {
            $conditions->setAttribute('NotOnOrAfter', gmdate('Y-m-d\TH:i:s\Z', $this->assertion_handler->mo_saml_get_not_on_or_after()));
        }
        
        if (null !== $this->assertion_handler->mo_saml_get_valid_audiences()) {
            $ar = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AudienceRestriction');
            $conditions->appendChild($ar);
            
            Mo_SAML_Utilities::addStrings($ar, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Audience', false, $this->assertion_handler->mo_saml_get_valid_audiences());
        }
    }
    
    /**
     * Add a AuthnStatement-node to the assertion.
     *
     * @param DOMElement $root
     *            The assertion element we should add the authentication statement to.
     */
    private function mo_saml_add_authn_statement(DOMElement $root)
    {
        if (null === $this->assertion_handler->mo_saml_get_authn_instant() || (null === $this->assertion_handler->mo_saml_get_authn_context_class_ref() && null === $this->assertion_handler->mo_saml_get_authn_aontext_aecl() && null === $this->assertion_handler->mo_saml_get_authn_context_decl_ref())) {
            /* No authentication context or AuthnInstant => no authentication statement. */
            
            return;
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
        $document = $root->ownerDocument;
        
        $authn_statement_el = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnStatement');
        $root->appendChild($authn_statement_el);
        
        $authn_statement_el->setAttribute('AuthnInstant', gmdate('Y-m-d\TH:i:s\Z', $this->assertion_handler->mo_saml_get_authn_instant()));
        
        if (null !== $this->assertion_handler->mo_saml_get_session_not_on_or_after()) {
            $authn_statement_el->setAttribute('SessionNotOnOrAfter', gmdate('Y-m-d\TH:i:s\Z', $this->assertion_handler->mo_saml_get_session_not_on_or_after()));
        }
        if (null !== $this->assertion_handler->mo_saml_get_session_index()) {
            $authn_statement_el->setAttribute('SessionIndex', $this->assertion_handler->mo_saml_get_session_index());
        }
        
        $authn_context_el = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContext');
        $authn_statement_el->appendChild($authn_context_el);
        
        if (! empty($this->assertion_handler->mo_saml_get_authn_context_class_ref())) {
            Mo_SAML_Utilities::addString($authn_context_el, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextClassRef', $this->assertion_handler->mo_saml_get_authn_context_class_ref());
        }
        if (! empty($this->assertion_handler->mo_saml_get_authn_aontext_aecl())) {
            $this->assertion_handler->mo_saml_get_authn_aontext_aecl()->mo_saml_to_xml($authn_context_el);
        }
        if (! empty($this->assertion_handler->mo_saml_get_authn_context_decl_ref())) {
            Mo_SAML_Utilities::addString($authn_context_el, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDeclRef', $this->assertion_handler->mo_saml_get_authn_context_decl_ref());
        }
        
        Mo_SAML_Utilities::addStrings($authn_context_el, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthenticatingAuthority', false, $this->assertion_handler->mo_saml_get_authenticating_authority());
    }
    
    /**
     * Add an AttributeStatement-node to the assertion.
     *
     * @param DOMElement $root
     *            The assertion element we should add the subject to.
     */
    private function mo_saml_add_attribute_statement(DOMElement $root)
    {
        if (empty($this->assertion_handler->mo_saml_get_attributes())) {
            return;
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
        $document = $root->ownerDocument;
        
        $attribute_statement = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeStatement');
        $root->appendChild($attribute_statement);
        
        foreach ($this->assertion_handler->mo_saml_get_attributes() as $name => $values) {
            $attribute = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Attribute');
            $attribute_statement->appendChild($attribute);
            $attribute->setAttribute('Name', $name);
            
            if ('urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified' !== $this->assertion_handler->mo_saml_get_attribute_name_format()) {
                $attribute->setAttribute('NameFormat', $this->assertion_handler->mo_saml_get_attribute_name_format());
            }
            
            foreach ($values as $value) {
                if (is_string($value)) {
                    $type = 'xs:string';
                } elseif (is_int($value)) {
                    $type = 'xs:integer';
                } else {
                    $type = null;
                }
                
                $attribute_value = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeValue');
                $attribute->appendChild($attribute_value);
                if (null !== $type) {
                    $attribute_value->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:type', $type);
                }
                if (is_null($value)) {
                    $attribute_value->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:nil', 'true');
                }
                
                if ($value instanceof DOMNodeList) {
                    for ($i = 0; $i < $value->length; $i ++) {
                        $node = $document->importNode($value->item($i), true);
                        $attribute_value->appendChild($node);
                    }
                } else {
                    $attribute_value->appendChild($document->createTextNode($value));
                }
            }
        }
    }
    
    /**
     * Add an EncryptedAttribute Statement-node to the assertion.
     *
     * @param DOMElement $root
     *            The assertion element we should add the Encrypted Attribute Statement to.
     */
    private function mo_saml_add_encrypted_attribute_statement(DOMElement $root)
    {
        if (false === $this->assertion_handler->mo_saml_get_encrypted_attributes()) {
            return;
        }
        // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement Attributes.
        $document = $root->ownerDocument;
        
        $attribute_statement = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeStatement');
        $root->appendChild($attribute_statement);
        
        foreach ($this->assertion_handler->mo_saml_get_attributes() as $name => $values) {
            $document2 = new DOMDocument();
            $attribute = $document2->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Attribute');
            $attribute->setAttribute('Name', $name);
            $document2->appendChild($attribute);
            
            if ('urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified' !== $this->assertion_handler->mo_saml_get_attribute_name_format()) {
                $attribute->setAttribute('NameFormat', $this->assertion_handler->mo_saml_get_attribute_name_format());
            }
            
            foreach ($values as $value) {
                if (is_string($value)) {
                    $type = 'xs:string';
                } elseif (is_int($value)) {
                    $type = 'xs:integer';
                } else {
                    $type = null;
                }
                
                $attribute_value = $document2->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeValue');
                $attribute->appendChild($attribute_value);
                if (null !== $type) {
                    $attribute_value->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:type', $type);
                }
                
                if ($value instanceof DOMNodeList) {
                    for ($i = 0; $i < $value->length; $i ++) {
                        $node = $document2->importNode($value->item($i), true);
                        $attribute_value->appendChild($node);
                    }
                } else {
                    $attribute_value->appendChild($document2->createTextNode($value));
                }
            }
            /* Once the attribute nodes are built, the are encrypted */
            $enc_assert = new XMLSecEnc();
            // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument Attributes.
            $enc_assert->setNode($document2->documentElement);
            $enc_assert->type = 'http://www.w3.org/2001/04/xmlenc#Element';
            
            /*
             * Attributes are encrypted with a session key and this one with
             * $EncryptionKey
             */
            $symmetric_key = new Mo_SAML_XML_Security_Key(Mo_SAML_XML_Security_Key::AES256_CBC);
            $symmetric_key->mo_saml_generate_session_key();
            $enc_assert->encryptKey($this->assertion_handler->mo_saml_get_encryption_key(), $symmetric_key);
            $encr_node = $enc_assert->encryptNode($symmetric_key);
            
            $enc_attribute = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:EncryptedAttribute');
            $attribute_statement->appendChild($enc_attribute);
            $n = $document->importNode($encr_node, true);
            $enc_attribute->appendChild($n);
        }
    }
    public function mo_saml_get_signature_data(){
        $this->assertion_handler->mo_saml_get_signature_data();
    }
    public function mo_saml_get_not_before() {
        return $this->assertion_handler->mo_saml_get_not_before();
    }
    public function mo_saml_get_not_on_or_after() {
        return $this->assertion_handler->mo_saml_get_not_on_or_after();
    }
    public function mo_saml_get_session_not_on_or_after() {
        return $this->assertion_handler->mo_saml_get_session_not_on_or_after();
    }
    public function mo_saml_get_issuer() {
        return $this->assertion_handler->mo_saml_get_issuer();
    }
    public function mo_saml_get_valid_audiences() {
        return $this->assertion_handler->mo_saml_get_valid_audiences();
    }
    public function mo_saml_get_name_id()
    {
        
        return $this->assertion_handler->mo_saml_get_name_id();
    }
    /**
     * Retrives signature data for the assertion.
     *
     * @return array
     */
 
    public function mo_saml_get_attributes()
    {
        return $this->assertion_handler->mo_saml_get_attributes();
    }
    public function mo_saml_get_session_index()
    {
        return $this->assertion_handler->mo_saml_get_session_index();
    }
    
}
