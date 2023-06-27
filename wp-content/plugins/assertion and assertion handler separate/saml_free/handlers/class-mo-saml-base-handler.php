<?php
/**
 * Handles all the form submissions in the plugin.
 *
 * @package miniorange-saml-20-single-sign-on\handlers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once dirname( __FILE__ ) . '/metadata/class-mo-saml-attribute-mapping-handler.php';
require_once dirname( __FILE__ ) . '/admin/class-mo-saml-contact-us-handler.php';
require_once dirname( __FILE__ ) . '/admin/class-mo-saml-customer-login-handler.php';
require_once dirname( __FILE__ ) . '/class-mo-saml-database-handler.php';
require_once dirname( __FILE__ ) . '/class-mo-saml-debug-log-handler.php';
require_once dirname( __FILE__ ) . '/class-mo-saml-demo-request-handler.php';
require_once dirname( __FILE__ ) . '/admin/class-mo-saml-feedback-form-handler.php';
require_once dirname( __FILE__ ) . '/metadata/class-mo-saml-role-mapping-handler.php';
require_once dirname( __FILE__ ) . '/metadata/class-mo-saml-service-provider-metadata-handler.php';
require_once dirname( __FILE__ ) . '/metadata/class-mo-saml-service-provider-settings-handler.php';
require_once dirname( __FILE__ ) . '/metadata/class-mo-saml-sso-settings-handler.php';
require_once dirname( __FILE__ ) . '/metadata/class-mo-saml-upload-metadata-handler.php';

/**
 * Main Form Handler class used to handle all the form submissions in the plugin.
 */
class Mo_SAML_Base_Handler {

	/**
	 * This function is responsible for verifying the nonce and calling the corresponding handlers when a form is submitted.
	 *
	 * @return void
	 */
	public static function mo_saml_save_settings_handler() {

		if ( isset( $_SERVER['QUERY_STRING'] ) && ! Mo_SAML_Utilities::mo_saml_is_plugin_page( sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have permission to view this page' );
		}

		$db_handler = new Mo_SAML_Database_Handler();

		$option = '';
		if ( isset( $_POST['option'] ) ) {
			$option = sanitize_text_field( wp_unslash( $_POST['option'] ) );
			check_admin_referer( $option );
		}

		switch ( $option ) {
			case 'login_widget_saml_save_settings':
				Mo_SAML_Service_Provider_Settings_Handler::mo_saml_service_provider_save_settings( $_POST, $db_handler );
				break;
			case 'saml_upload_metadata':
				Mo_SAML_Upload_Metadata_Handler::mo_saml_upload_metadata( $_POST, $_FILES, $db_handler );
				break;
			case 'mosaml_metadata_download':
				Mo_SAML_Service_Provider_Metadata_Handler::download_plugin_metadata( true );
				break;
			case 'mo_saml_update_idp_settings_option':
				Mo_SAML_Service_Provider_Metadata_Handler::update_sp_endpoints( $_POST, $db_handler );
				break;
			case 'mo_saml_contact_us_query_option':
				Mo_SAML_Contact_Us_Handler::mo_saml_send_contact_us( $_POST );
				break;
			case 'clear_attrs_list':
				Mo_SAML_Attribute_Mapping_Handler::clear_attr_list();
				break;
			case 'login_widget_saml_role_mapping':
				Mo_SAML_Role_Mapping_Handler::mo_saml_update_default_role( $_POST, $db_handler );
				break;
			case 'mo_saml_add_sso_button_wp_option':
				Mo_SAML_SSO_Settings_Handler::mo_saml_add_sso_button( $_POST, $db_handler );
				break;
			case 'mo_saml_demo_request_option':
				Mo_SAML_Demo_Request_Handler::mo_saml_request_demo( $_POST );
				break;
			case 'mo_saml_register_customer':
				Mo_SAML_Customer_Login_Handler::mo_saml_register_customer( $_POST, $db_handler );
				break;
			case 'change_miniorange':
				Mo_SAML_Customer_Login_Handler::mo_saml_change_account();
				break;
			case 'mo_saml_logger':
				Mo_SAML_Debug_Log_Handler::mo_saml_process_logging( $_POST );
				break;
			case 'mo_skip_feedback':
				Mo_SAML_Feedback_Form_Handler::mo_saml_skip_feedback();
				break;
			case 'mo_feedback':
				Mo_SAML_Feedback_Form_Handler::mo_saml_send_feedback( $_POST );
				break;
		}

	}
}
