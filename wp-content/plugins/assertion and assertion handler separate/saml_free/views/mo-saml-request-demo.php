<?php
/**
 * Displays the demo request form.
 *
 * @package miniorange-saml-20-single-sign-on\views
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Used to show the UI part of the demo request form to user screen.
 *
 * @return void
 */
function mo_saml_display_demo_request() {
	$license_plans       = Mo_Saml_License_Plans::$license_plans;
	$addons              = Mo_Saml_Options_Addons::$addon_title;
	$mo_saml_admin_email = get_option( Mo_Saml_Customer_Constants::ADMIN_EMAIL );
	$mo_saml_admin_email = ! empty( $mo_saml_admin_email ) ? $mo_saml_admin_email : get_option( 'admin_email' );
	$addons              = mo_saml_options_addons::$addon_title;
	?>
	<div class="mo-saml-bootstrap-row mo-saml-bootstrap-container-fluid" id="demo-tab-form">
		<div class="mo-saml-bootstrap-col-md-8 mo-saml-bootstrap-mt-4 mo-saml-bootstrap-ms-5">
			<form method="post" action="">
				<?php wp_nonce_field( 'mo_saml_demo_request_option' ); ?>
				<input type="hidden" name="option" value="mo_saml_demo_request_option" />

				<div class="mo-saml-bootstrap-p-4 shadow-cstm mo-saml-bootstrap-bg-white mo-saml-bootstrap-rounded">
					<h4 class="form-head">Request for Demo</h4>

					<h6 class="mo-saml-bootstrap-text-center bg-cstm mo-saml-bootstrap-p-4 mo-saml-bootstrap-rounded mo-saml-bootstrap-mt-3">Want to try out the paid features before purchasing the
						license? Just let us know
						which plan you're interested in and we will setup a demo for you.</h6>
					<div class="mo-saml-bootstrap-row align-items-top mo-saml-bootstrap-mt-4">
						<div class="mo-saml-bootstrap-col-md-3">
							<h6 class="mo-saml-bootstrap-text-secondary">Email </span>:</h6>
						</div>
						<div class="mo-saml-bootstrap-col-md-6">
							<input type="email" name="mo_saml_demo_email" placeholder="We will use this email to setup the demo for you" required value="<?php echo esc_attr( $mo_saml_admin_email ); ?>" class="mo-saml-bootstrap-w-100">
						</div>
					</div>
					<div class="mo-saml-bootstrap-row align-items-top mo-saml-bootstrap-mt-4">
						<div class="mo-saml-bootstrap-col-md-3">
							<h6 class="mo-saml-bootstrap-text-secondary">Request a demo for </span>:</h6>
						</div>
						<div class="mo-saml-bootstrap-col-md-6">
							<select name="mo_saml_demo_plan" id="mo_saml_demo_plan" class="mo-saml-bootstrap-w-100" required="">
								<option hidden disabled selected value="">--<?php esc_html_e( 'Select a license plan', 'miniorange-saml-20-single-sign-on' ); ?>--</option>
								<?php
								foreach ( $license_plans as $key => $value ) {
									?>
									<option value="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $value ); ?>
									<?php
								}
								?>
							</select>
						</div>
					</div>
					<div class="mo-saml-bootstrap-row align-items-top mo-saml-bootstrap-mt-4">
						<div class="mo-saml-bootstrap-col-md-3">
							<h6 class="mo-saml-bootstrap-text-secondary">Description :</h6>
						</div>
						<div class="mo-saml-bootstrap-col-md-6">
							<textarea rows="6" cols="5" name="mo_saml_demo_description" placeholder="Write us about your requirement" class="mo-saml-bootstrap-w-100"></textarea>
						</div>
					</div>


					<h6 class="mo-saml-bootstrap-text-secondary mo-saml-bootstrap-mt-4">Select the Add-ons you are interested in (Optional) :</h6>
					<?php
					$column = 0;
					foreach ( $addons as $key => $value ) {
						if ( 0 === $column % 3 ) {
							?>
							<div class="mo-saml-bootstrap-row align-items-top mo-saml-opt-add-ons">
								<?php } ?>
								<div class="mo-saml-bootstrap-col-md-4">
									<input type="checkbox" name="<?php echo esc_attr( $key ); ?>" value="true"> <span><?php echo esc_html( $value ); ?></span>
								</div>
								<?php if ( 2 === $column % 3 ) { ?>
							</div>
						<?php } ?>

						<?php
						$column++;
					}
					?>
					<div class="mo-saml-bootstrap-text-center">
						<input type="submit" class="btn-cstm mo-saml-bootstrap-bg-info mo-saml-bootstrap-rounded mo-saml-bootstrap-mt-4" name="submit" value="Send Request">
					</div>
				</div>
			</form>
		</div>
	</div>
	<?php mo_saml_display_support_form(); ?>   
	<?php
}
