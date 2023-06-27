<?php
/**
 * Handles Form processing of the Demo Request.
 *
 * @package  miniorange-saml-20-single-sign-on\handlers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit();
}

/**
 * Class Mo_SAML_Demo_Request_Handler
 * Responsible to validate the demo request query like Customer email, Selected addon and description etc.
 */
class Mo_SAML_Demo_Request_Handler {

	/**
	 * Status for the demo request
	 *
	 * @var string $status
	 */
	private static $status = '';

	/**
	 * Create the demo request according the demo plan, description and selected addon.
	 *
	 * @param array $post_array Contains the $_POST form data.
	 * @return void
	 */
	public static function mo_saml_request_demo( $post_array ) {
		$demo_request                                       = array();
		$demo_request[ Mo_Saml_Demo_Constants::DEMO_EMAIL ] = isset( $post_array[ Mo_Saml_Demo_Constants::DEMO_EMAIL ] ) ? sanitize_email( $post_array[ Mo_Saml_Demo_Constants::DEMO_EMAIL ] ) : get_option( Mo_Saml_Customer_Constants::ADMIN_EMAIL );
		$demo_request[ Mo_Saml_Demo_Constants::DEMO_PLAN ]  = isset( $post_array[ Mo_Saml_Demo_Constants::DEMO_PLAN ] ) ? sanitize_text_field( $post_array[ Mo_Saml_Demo_Constants::DEMO_PLAN ] ) : '';

		if ( ! self::mo_saml_validate_demo_request_fields( $demo_request ) ) {
			return;
		}

		$demo_request[ Mo_Saml_Demo_Constants::DEMO_DESCRIPTION ] = sanitize_text_field( $post_array[ Mo_Saml_Demo_Constants::DEMO_DESCRIPTION ] );
		$demo_request[ Mo_Saml_Demo_Constants::DEMO_ADDONS ]      = self::mo_saml_get_selected_addons( $post_array, Mo_Saml_Options_Addons::$addon_title );

		if ( ! empty( Mo_Saml_License_Plans::$license_plans_slug[ $demo_request[ Mo_Saml_Demo_Constants::DEMO_PLAN ] ] ) ) {
			self::mo_saml_create_wordpress_demo( $demo_request );
		} else {
			self::$status = __( 'Please setup manual demo.', 'miniorange-saml-20-single-sign-on' );
		}

		$query = self::mo_saml_set_demo_query( $demo_request );
		self::mo_saml_send_demo_request( $query );
	}

	/**
	 * Validate the demo request fields like email and demo plan.
	 *
	 * @param array $demo_request array of demo request fields.
	 * @return boolean
	 */
	private static function mo_saml_validate_demo_request_fields( $demo_request ) {

		$validate_fields_array = array( $demo_request[ Mo_Saml_Demo_Constants::DEMO_EMAIL ], $demo_request[ Mo_Saml_Demo_Constants::DEMO_PLAN ] );
		if ( Mo_SAML_Utilities::mo_saml_check_empty_or_null( $validate_fields_array ) ) {
			$post_save    = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::ERROR, Mo_Saml_Messages::CONTACT_EMAIL_EMPTY );
			self::$status = __( 'Error: Email address or Demo plan is Empty', 'miniorange-saml-20-single-sign-on' );
		}
		if ( ! filter_var( $demo_request[ Mo_Saml_Demo_Constants::DEMO_EMAIL ], FILTER_VALIDATE_EMAIL ) ) {
			$post_save = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::ERROR, Mo_Saml_Messages::CONTACT_EMAIL_INVALID );
		}
		if ( isset( $post_save ) ) {
			$post_save->mo_saml_post_save_action();
			return false;
		}
		return true;
	}

	/**
	 * Get the selected addon for the demo request.
	 *
	 * @param array $post_array Contains the $_POST form data.
	 * @param array $addons Array for addons.
	 * @return string $addons_selected
	 */
	private static function mo_saml_get_selected_addons( $post_array, $addons ) {
		$addons_selected = array();
		foreach ( $addons as $key => $value ) {
			if ( isset( $post_array[ $key ] ) && 'true' === $post_array[ $key ] ) {
				$addons_selected[ $key ] = $value;
			}
		}
		return $addons_selected;
	}

	/**
	 * Creates the WordPress demo for the demo request.
	 *
	 * @param array $demo_request Contains the details for demo request.
	 * @return void
	 */
	private static function mo_saml_create_wordpress_demo( $demo_request ) {

		$plugin_version = Mo_Saml_License_Plans::$license_plans_slug[ $demo_request[ Mo_Saml_Demo_Constants::DEMO_PLAN ] ];
		$headers        = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
			'charset'      => 'UTF - 8',
		);
		$args           = array(
			'method'      => 'POST',
			'body'        => array(
				'option'                            => 'mo_auto_create_demosite',
				'mo_auto_create_demosite_email'     => $demo_request[ Mo_Saml_Demo_Constants::DEMO_EMAIL ],
				'mo_auto_create_demosite_usecase'   => $demo_request[ Mo_Saml_Demo_Constants::DEMO_DESCRIPTION ],
				'mo_auto_create_demosite_demo_plan' => $plugin_version,
			),
			'timeout'     => '20',
			'redirection' => '5',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
		);

		$response = wp_remote_post( Mo_Saml_Demo_Constants::DEMO_SITE_URL, $args );
		if ( is_wp_error( $response ) ) {
			$error_message = $response->get_error_message();
			echo 'Something went wrong:' . esc_html( $error_message );
			exit();
		}
		$output = wp_remote_retrieve_body( $response );
		$output = json_decode( $output );

		if ( is_null( $output ) ) {
			$post_save    = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::ERROR, Mo_Saml_Messages::DEMO_REQUEST_FAILED );
			self::$status = __( 'Error: Something went wrong while setting up demo.', 'miniorange-saml-20-single-sign-on' );
		} elseif ( Mo_Saml_Api_Status_Constants::SUCCESS !== $output->status ) {
			$post_save    = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::ERROR, $output->message );
			self::$status = __( 'Error :', 'miniorange-saml-20-single-sign-on' ) . $output->message;
		} else {
			$post_save    = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::SUCCESS, $output->message );
			self::$status = __( 'Success :', 'miniorange-saml-20-single-sign-on' ) . $output->message;
		}

		if ( isset( $post_save ) ) {
			$post_save->mo_saml_post_save_action();
		}
	}

	/**
	 * Create the Demo Request Query
	 *
	 * @param array $demo_request Contains the detais for demo request.
	 * @return string $message
	 */
	private static function mo_saml_set_demo_query( $demo_request ) {

		$plan_name = Mo_Saml_License_Plans::$license_plans[ $demo_request[ Mo_Saml_Demo_Constants::DEMO_PLAN ] ];

		$message  = '[Demo For Customer] : ' . $demo_request[ Mo_Saml_Demo_Constants::DEMO_EMAIL ];
		$message .= ' <br>[Selected Plan] : ' . $plan_name;

		if ( ! empty( $demo_request[ Mo_Saml_Demo_Constants::DEMO_DESCRIPTION ] ) ) {
			$message .= ' <br>[Requirements] : ' . $demo_request[ Mo_Saml_Demo_Constants::DEMO_DESCRIPTION ];
		}

		$message .= ' <br>[Status] : ' . self::$status;

		if ( ! empty( $demo_request[ Mo_Saml_Demo_Constants::DEMO_ADDONS ] ) ) {
			$message .= ' <br>[Addons] : ';
			foreach ( $demo_request[ Mo_Saml_Demo_Constants::DEMO_ADDONS ] as $key => $value ) {
				$message .= $value;
				if ( next( $demo_request[ Mo_Saml_Demo_Constants::DEMO_ADDONS ] ) ) {
					$message .= ', ';
				}
			}
		}
		return $message;
	}

	/**
	 * Send query for demo request
	 *
	 * @param array $query Contains detais for the demo request.
	 * @return void
	 */
	private static function mo_saml_send_demo_request( $query ) {

		$user        = wp_get_current_user();
		$customer    = new Mo_SAML_Customer();
		$email       = empty( get_option( 'mo_saml_admin_email' ) ) ? $email = $user->user_email : get_option( 'mo_saml_admin_email' );
		$phone       = get_option( 'mo_saml_admin_phone' );
		$demo_status = strpos( self::$status, 'Error' );

		$response = json_decode( $customer->mo_saml_send_email_alert( $email, $phone, $query, true ), true );

		if ( ! empty( $response['status'] ) && Mo_Saml_Api_Status_Constants::ERROR === $response['status'] ) {
			$post_save = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::ERROR, $response['message'] );
		} elseif ( false === $response || false !== $demo_status ) {
			$post_save = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::ERROR, self::$status );
		} elseif ( json_last_error() === JSON_ERROR_NONE ) {
			$post_save = new Mo_SAML_Post_Save_Handler( Mo_Saml_Save_Status_Constants::SUCCESS, Mo_Saml_Messages::QUERY_SUBMITTED );
		}

		if ( isset( $post_save ) ) {
			$post_save->mo_saml_post_save_action();
		}
	}

}
