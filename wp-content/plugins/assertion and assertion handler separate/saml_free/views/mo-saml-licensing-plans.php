<?php
/** This file contains the functions to display the licensing plans and features of the miniOrange SAML SP plugin.
 *
 * @package     miniorange-saml-20-single-sign-on\views
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL, see LICENSE.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Displays the licensing plans.
 */
function mo_saml_show_licensing_page() {
	$supportmail  = 'samlsupport@xecurify.com';
	$current_user = wp_get_current_user();
	$fname        = $current_user->user_firstname;
	$lname        = $current_user->user_lastname;
	if ( isset( $_SERVER['REQUEST_URI'] ) ) {
		$server_url = esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
	} else {
		$server_url = '';
	}
	?>
	<?php
	echo '<style>.update-nag, .updated, .error, .is-dismissible, .notice, .notice-error { display: none; }</style>';
	?>

	<div class="mo-saml-bootstrap-bg-white">
		<div class="lic-body">
			<div class="nav-menu">
				<div class="plugin-banner-text-saml goto-opt">
					<a href="#pricing" class="pricing"> Pricing Plans </a>
				</div>
				<div class="plugin-banner-text-saml goto-opt">
					<a href="#switch-id-saml" class="switch-id-saml"> Feature Comparison </a>
				</div>
				<div class="plugin-banner-text-saml goto-opt">
					<a href="#pricing-faqs" class="pricing-faqs"> Pricing FAQs</a>
				</div>
				<div class="plugin-banner-text-saml goto-opt">
					<a href="#payment-methods" class="payment-methods"> Payment Methods </a>
				</div>
				<div class="plugin-banner-text-saml goto-opt">
					<a href="#upgrade-steps" class="steps-to-upgrade">Upgrade Steps</a>
				</div>
			</div>
			<input type="hidden" value="<?php echo esc_attr( mo_saml_is_customer_registered_saml() ); ?>" id="mo_customer_registered">
			<h2 class="plan-head-saml saml-scroll" id="pricing">Choose your Licensing Plan</h2>
			<div class="tabs mo-saml-bootstrap-text-center">
				<ul class="saml-pills">
					<li><a id="single-site" data-tab="1" class="tab active">Standalone</a></li>
					<li><a id="multi-site" data-tab="2" class="tab">Multi-site Network</a></li>
				</ul>
			</div>
			<div class="mo-saml-bootstrap-row handler single-site mo-saml-bootstrap-text-center mo-saml-bootstrap-ms-4">
				<div class="mo-saml-bootstrap-col-md-9 reg-plans-saml single-site-rot common-rot reg-plans-saml-sing">
					<div class="mo-saml-bootstrap-row">
						<div class="mo-saml-bootstrap-col-md-4 hover-saml">
							<h3 class="header-h3">STANDARD</h3>
							<div class="price-list mo-saml-bootstrap-mt-5">
								<li class="choose-plan-saml mo-saml-bootstrap-text-start"><i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Auto-Redirect to IdP</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start"><i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Basic Attribute Mapping (Username, Email, First Name, Last Name, Display Name)</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start"><br></li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start"><br></li>
							</div>
							<p><span class="mo-saml-bootstrap-display-1"><span>$</span>349 <sup>*</sup></span></p><br>
							<a onclick="upgradeform('wp_saml_sso_standard_plan')" class="license-btn-saml">UPGRADE NOW</a>
						</div>
						<div class="mo-saml-bootstrap-col-md-4 hover-saml">
							<h3 class="header-h3">PREMIUM</h3>
							<div class="price-list mo-saml-bootstrap-mt-5">
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Advanced Attribute and Role Mapping
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>SAML Single Logout
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>IDP Metadata Sync
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>All Standard features<br>&nbsp;
								</li>
							</div>
							<p><span class="mo-saml-bootstrap-display-1"><span>$</span>449 <sup>*</sup></span></p><br>
							<a onclick="upgradeform('wp_saml_sso_basic_plan')" class="license-btn-saml">UPGRADE NOW</a>
						</div>
						<div class="mo-saml-bootstrap-col-md-4 hover-saml">
							<h3 class="header-h3">ENTERPRISE</h3>
							<div class="price-list mo-saml-bootstrap-mt-5">
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Migrate Plugin Configuration in Multiple Environment (dev-test-prod)
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Multiple SAML IDP Support
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>SSO Login Audit
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>All Premium features<br>&nbsp;
								</li>
							</div>
							<p><span class="mo-saml-bootstrap-display-1"><span>$</span>549 <sup>*</sup></span></p><br>
							<a onclick="upgradeform('wp_saml_sso_multiple_idp_plan')" class="license-btn-saml">UPGRADE NOW</a>
						</div>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-3 single-site-rot common-rot">
					<div class="incl-plan-saml">
						<div class="product">
							<div class="price-tag">
								<p class="price">Best Value</p>
							</div>
						</div>
						<h3 class="header-h3">ALL-INCLUSIVE</h3>
						<div class="price-list mo-saml-bootstrap-mt-5 mo-saml-bootstrap-text-start price-list-incl">
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>SCIM Automatic User Sync
							</li>
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>LearnDash, BuddyBoss & MemberPress Integration
							</li>
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Page/Post Restriction
							</li>
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i><a href="https://plugins.miniorange.com/wordpress-single-sign-on-sso-integrations" target="_blank" class="text-color"><u>All other addons</u></a> + All Enterprise features
							</li>
						</div>
						<p><span class="mo-saml-bootstrap-display-1"><span>$</span>649 <sup>*</sup></span></p><br>
						<a onclick="upgradeform('wp_saml_sso_all_inclusive_plan')" class="license-btn-saml">UPGRADE NOW</a>
					</div>
				</div>
			</div>
			<!-- MULTISITE -->
			<div class="mo-saml-bootstrap-row handler multi-site mo-saml-bootstrap-text-center mo-saml-bootstrap-ms-4" style="display: none;">
				<div class="mo-saml-bootstrap-col-md-8 reg-plans-saml multi-site-rot common-rot multi-site-height">
					<div class="mo-saml-bootstrap-row">
						<div class="mo-saml-bootstrap-col-md-6 hover-saml multi-site-height">
							<h3 class="header-h3">PREMIUM</h3>
							<div class="price-list mo-saml-bootstrap-mt-5 price-list-multi">
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Auto-Redirect to IdP
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Attribute and Role Management
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Connect all subsites to same SAML IdP
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>SAML Single Logout<br>&nbsp;
								</li>
							</div>
							<p><span class="mo-saml-bootstrap-display-1"><span>$</span>449 <sup>*</sup></span></p><br>
							<a onclick="upgradeform('wp_saml_sso_multisite_basic_plan')" class="license-btn-saml">UPGRADE NOW</a>
						</div>
						<div class="mo-saml-bootstrap-col-md-6 hover-saml multi-site-height">
							<h3 class="header-h3">ENTERPRISE</h3>
							<div class="price-list mo-saml-bootstrap-mt-5 price-list-multi">
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Mu Domain Mapping Support
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Easy migration from staging to prod
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Setup SSO with multiple SAML IdPs
								</li>
								<li class="choose-plan-saml mo-saml-bootstrap-text-start">
									<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>All Premium features<br>&nbsp;
								</li>
							</div>
							<p><span class="mo-saml-bootstrap-display-1"><span>$</span>549 <sup>*</sup></span></p><br>
							<a onclick="upgradeform('wp_saml_sso_multisite_multiple_idp_plan')" class="license-btn-saml">UPGRADE NOW</a>
						</div>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-4 multi-site-rot common-rot">
					<div class="incl-plan-saml multi-site-height">
						<div class="product">
							<div class="price-tag price-tag-mult">
								<p class="price">Best Value</p>
							</div>
						</div>
						<h3 class="header-h3">ALL-INCLUSIVE</h3>
						<div class="price-list mo-saml-bootstrap-mt-5 mo-saml-bootstrap-text-start price-list-incl price-list-multi">
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Multisite Network SSO
							</li>
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>SCIM Automatic User Sync
							</li>
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i>Page/Post Restriction
							</li>
							<li class="choose-plan-saml">
								<i class="fas fa-arrow-circle-right mo-saml-bootstrap-text-success">&nbsp;&nbsp;</i><a href="https://plugins.miniorange.com/wordpress-single-sign-on-sso-integrations" target="_blank" class="text-color"><u>All other addons</u></a> + All Enterprise features
							</li>
						</div>
						<p><span class="mo-saml-bootstrap-display-1"><span>$</span>649 <sup>*</sup></span></p><br>
						<a onclick="upgradeform('wp_saml_sso_multisite_all_inclusive_plan')" class="license-btn-saml">UPGRADE NOW</a>
					</div>
				</div>
			</div>
			<div class="saml-scroll" id="switch-id-saml"></div>
			<div class="mo-saml-bootstrap-text-center handler single-site" id="compare-plans">
				<a class="mo-saml-bootstrap-btn clk-icn collapsed" data-bs-toggle="collapse" data-bs-target="#demo" aria-expanded="false">Compare Plans&nbsp;&nbsp; <i class="fas fa-times"></i></a>
			</div>
			<div class="handler multi-site mo-saml-bootstrap-text-center" id="compare-multi-plans" style="display: none;">
				<a class="mo-saml-bootstrap-btn clk-icn collapsed" data-bs-toggle="collapse" data-bs-target="#demo1" aria-expanded="false">Compare Plans&nbsp;&nbsp; <i class="fas fa-close"></i></a>
			</div>
			<div class="mo-saml-bootstrap-row mo-saml-bootstrap-text-center mo-saml-bootstrap-mt-5 collapse cp-single-site" id="demo">
				<table class="mo-saml-bootstrap-w-100 mo-saml-bootstrap-ms-3">
					<tr class="box-shadow-saml sticky-menu-saml">
						<th class="feat-head-saml">Features</th>
						<th class="feat-head-saml">Standard</th>
						<th class="feat-head-saml">Premium</th>
						<th class="feat-head-saml">Enterprise</th>
						<th class="feat-head-saml">All-Inclusive</th>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Unlimited Authentications</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Basic Attribute Mapping (Username, Email, First Name, Last Name,Display Name)</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Widget, Shortcode to add SAML IDP Login Link</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Auto-Redirect to IdP from login page</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Protect your complete site (Auto-Redirect to IdP from any page)</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Change SP base URL and SP Entity ID</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Different SAML Request binding type</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">SAML Single Logout</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Customized Role Mapping</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Auto-sync IdP Configuration from metadata</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Custom Attribute Mapping (Any attribute which is stored in user-meta table)</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Custom SP Certificate</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Easy Migration Support for Multiple Environments (Dev-test-prod)</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Multiple SAML IDP Support</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">SSO Login Audit</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Customize the SP metadata contact information</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">SCIM Automatic User Sync</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Page/Post Restriction (Premium)</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start tooltip-saml">Other Add-ons <i class="fas fa-info-circle"></i>
							<ol class="tooltiptext">
								<li>LearnDash Integration</li>
								<li>BuddyPress/BuddyBoss Integration</li>
								<li>Guest User Login</li>
								<li>WooCommerce Integrator</li>
								<li>SSO Session Management</li>
								<li>Attribute Based Redirection</li>
								<li>Paid Membership Pro Integrator</li>
								<li>Profile Picture Map</li>
								<li>Federation Single Sign-On</li>
							</ol>
						</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr>
						<td></td>
						<td><a onclick="upgradeform('wp_saml_sso_standard_plan')" class="license-btn-saml upg-btn border-rad-saml">UPGRADE NOW</a></td>
						<td><a onclick="upgradeform('wp_saml_sso_basic_plan')" class="license-btn-saml upg-btn border-rad-saml">UPGRADE NOW</a></td>
						<td><a onclick="upgradeform('wp_saml_sso_multiple_idp_plan')" class="license-btn-saml upg-btn border-rad-saml">UPGRADE NOW</a></td>
						<td><a onclick="upgradeform('wp_saml_sso_all_inclusive_plan')" class="license-btn-saml upg-btn border-rad-saml">UPGRADE NOW</a></td>
					</tr>
				</table>
			</div>
			<div class="mo-saml-bootstrap-row mo-saml-bootstrap-text-center mo-saml-bootstrap-mt-5 collapse cp-multi-site" id="demo1">
				<table class="mo-saml-bootstrap-w-100 mo-saml-bootstrap-ms-3">
					<tr class="box-shadow-saml sticky-menu-saml">
						<th class="feat-head-saml">Features</th>
						<th class="feat-head-saml">Premium</th>
						<th class="feat-head-saml">Enterprise</th>
						<th class="feat-head-saml">All-Inclusive</th>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Unlimited Authentications</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Basic Attribute Mapping (Username, Email, First Name, Last Name,Display Name)</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Widget, Shortcode to add SAML IDP Login Link</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Auto-Redirect to IdP from login page</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Protect your complete site (Auto-Redirect to IdP from any page)</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Change SP base URL and SP Entity ID</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Different SAML Request binding type</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">SAML Single Logout</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Customized Role Mapping</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Auto-sync IdP Configuration from metadata</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Custom Attribute Mapping (Any attribute which is stored in user-meta table)</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Custom SP Certificate</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Sub-site specific SSO for Multisite</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Auto-Redirection from specific subsites</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Mu Domain Mapping Support</td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Easy Migration Support for Multiple Environments (Dev-test-prod)</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Multiple SAML IDP Support</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">SSO Login Audit</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Customize the SP metadata contact information</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">SCIM Automatic User Sync</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start">Page/Post Restriction (Premium)</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr class="box-shadow-saml">
						<td class="mo-saml-bootstrap-text-start tooltip-saml">Other Add-ons <i class="fas fa-info-circle"></i>
							<ol class="tooltiptext">
								<li>LearnDash Integration</li>
								<li>BuddyPress/BuddyBoss Integration</li>
								<li>Guest User Login</li>
								<li>WooCommerce Integrator</li>
								<li>SSO Session Management</li>
								<li>Attribute Based Redirection</li>
								<li>Paid Membership Pro Integrator</li>
								<li>Profile Picture Map</li>
								<li>Federation Single Sign-On</li>
							</ol>
						</td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-times mo-saml-bootstrap-text-danger"></i></td>
						<td><i class="fas fa-check mo-saml-bootstrap-text-success"></i></td>
					</tr>
					<tr>
						<td></td>
						<td><a onclick="upgradeform('wp_saml_sso_multisite_basic_plan')" class="license-btn-saml upg-btn border-rad-saml mo-saml-bootstrap-mt-4">UPGRADE NOW</a></td>
						<td><a onclick="upgradeform('wp_saml_sso_multisite_multiple_idp_plan')" class="license-btn-saml upg-btn border-rad-saml mo-saml-bootstrap-mt-4">UPGRADE NOW</a></td>
						<td><a onclick="upgradeform('wp_saml_sso_multisite_all_inclusive_plan')" class="license-btn-saml upg-btn border-rad-saml mo-saml-bootstrap-mt-4">UPGRADE NOW</a></td>
					</tr>
				</table>
			</div>
			<form style="display:none;text-align: left;" id="loginform" action="<?php echo esc_url( Mo_Saml_Options_Plugin_Constants::HOSTNAME . '/moas/login' ); ?>" target="_blank" method="post">
				<input type="text" name="redirectUrl" value="<?php echo esc_url( Mo_Saml_Options_Plugin_Constants::HOSTNAME . '/moas/initializepayment' ); ?>" />
				<input type="text" name="requestOrigin" id="requestOrigin" value="">
			</form>
			<div class="mo-saml-bootstrap-row mo-saml-bootstrap-ms-4 mo-saml-bootstrap-me-4 mo-saml-bootstrap-mt-5 saml-scroll">
				<h2 class="plan-head-saml" id="pricing-faqs">Pricing FAQs</h2>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">Do I need to pay one-time or annually?</h3>
						<p class="faq-text">The plugin licenses are subscriptions and the Support Plan includes 12 months of maintenance (support and version updates). The licenses have to be renewed yearly. We offer a 50% discount at the time of renewal if the number of purchased licenses is more than 1. Hence, your license renewal cost will be 100% if the license count is 1, and 50% if the license count is more than 1.
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(0)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">How do I get a refund ?</h3>
						<p class="faq-text">At miniOrange, we want to ensure you are 100% happy with your purchase. If the plugin you purchased is not working as advertised and you've attempted to resolve any issues with our support team, which couldn't get resolved. We will refund the whole amount within 10 days of the purchase. Please email us at <a href="mailto:samlsupport@xecurify.com" class="text-primary"><b>samlsupport@xecurify.com</b></a> for any queries regarding the return policy or contact us <a href="https://www.miniorange.com/contact" target="_blank"><b>here</b>.</a></a>
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(1)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
			</div>
			<div class="mo-saml-bootstrap-row mo-saml-bootstrap-ms-4 mo-saml-bootstrap-me-4">
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">Does miniOrange offer support in setting up the plugin?</h3>
						<p class="faq-text">Yes, we provide 24*7 support for setting up the plugin and resolving any issues you might face while using the plugin. You can get prioritized support based on the Support Plan you have opted for. You can check out the
							different Support Plans from <a href="https://www.miniorange.com/support-plans" target="_blank" class="text-primary"><b><u>here</u></b></a>.
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(2)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">How many sites are covered with the All-Inclusive plan?</h3>
						<p class="faq-text">The All-Inclusive plan means you will get access to all the <a href="https://plugins.miniorange.com/wordpress-single-sign-on-sso-integrations" target="_blank"><b>addons</b></a> without paying additional cost to any add-on mentioned in the plan.
						<br>Our plugins are activated on the domain level, so 1 license for the All-Inclusive plan can be used for 1 site only; if you have more than 1 site, you will need to purchase the license for those number of sites. <b>Do note that we do provide discounts from 2nd license onwards.</b>
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(3)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
			</div>
			<div class="mo-saml-bootstrap-row mo-saml-bootstrap-ms-4 mo-saml-bootstrap-me-4">
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">What happens if I do not renew my license?</h3>
						<p class="faq-text">If you decide to cancel or not renew your license, your plugin will stop working.</p>
						<button class="faq-toggle" onclick="toggleFAQ(4)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">What is one instance?</h3>
						<p class="faq-text">A WordPress instance refers to a single installation of a WordPress site. It refers to each individual website where the plugin is active. In the case of a single site WordPress, each website will be counted as a single instance.
							<br>
							<b>License is linked to the domain of the WordPress instance, so if you have dev-staging-prod type of environment then you will require 3 licenses of the plugin (with discounts applicable on pre-production environments)
							</b>.
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(5)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">What is Multiple IDP Support?</h3>
						<p class="faq-text">
							Multiple IDP support allows you to enable authentication on your site from multiple IDPs. For example - If your users exist in Azure AD as well as Okta, then you can opt for the multiple IDP Plugin and allow user authentication from either
							IDP. <b>We support SSO authentication from multiple Identity Providers in our Enterprise and All-Inclusive versions of the plugin</b>. Check out additional details of the multiple IDP flow from <a href="https://plugins.miniorange.com/wordpress-single-sign-on-sso-with-multiple-idp" target="_blank" class="text-primary"><b><u>here</u></b></a>. You can add multiple IDPs to your licnese at $50 per IDP. Please reach out to us at <a href="mailto:samlsupport@xecurify.com" target="_blank"><b>samlsupport@xecurify.com</b></a>
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(6)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">What is a multisite network?</h3>
						<p class="faq-text">
						WordPress Multisite is a feature that allows you to create a "network" of subsites within a single instance of WordPress, where the subsites share a file system and database. There are two types of multisite environments - subdomain (Example: abc.domain.com) and subdirectory (Example: domain.com/abc)
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(7)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">Can I purchase unlimited licenses?</h3>
						<p class="faq-text">
							Yes, you can purchase unlimited licenses. Do note that purchasing licenses for Unlimited instances will grant you up to 200 licenses initially. If you'd like to purchase more licenses, please drop an email at <a href="mailto:samlsupport@xecurify.com">samlsupport@xecurify.com</a>.
						</p>
						<button class="faq-toggle" onclick="toggleFAQ(8)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-6 mo-saml-bootstrap-mt-5">
					<div class="faq">
						<h3 class="faq-title">Do I need to pay for every subsite in my multisite network?</h3>
						<p class="faq-text">No, you only need to pay for the "Active" subsites in your WordPress multisite network. All of the subsites which are in the Deactivated or Archived state will not be counted.</p>
						<button class="faq-toggle" onclick="toggleFAQ(9)">
							<i class="fas fa-chevron-down"></i>
							<i class="fas fa-times"></i>
						</button>
					</div>
				</div>
			</div>
			<br>
			<h2 class="plan-head-saml saml-scroll" id="payment-methods">Payment Methods </h2>
			<div class="mo-saml-bootstrap-row mo-saml-bootstrap-text-center mo-saml-bootstrap-mx-3">
				<div class="mo-saml-bootstrap-col-md-4 mo-saml-bootstrap-mt-5">
					<div class="plan-box">
						<div class="plan-box-up">
							<i class="fab fa-cc-amex fa-3x"></i>
							<i class="fab fa-cc-visa fa-3x"></i>
							<i class="fab fa-cc-mastercard fa-3x"></i>
						</div>
						<p>Credit cards (American Express, Discover, MasterCard, and Visa) - If the payment is made through Credit Card/International Debit Card, the license will be created automatically once the payment is completed.</p>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-4 mo-saml-bootstrap-mt-5">
					<div class="plan-box">
						<div class="plan-box-up">
							<img class="payment-images" src="<?php echo esc_url( Mo_SAML_Utilities::mo_saml_get_plugin_dir_url() . '../images/paypal-logo.webp' ); ?>" alt="WordPress sso payment methods" width="35%">
						</div>
						<p>Please contact us <a href="https://www.miniorange.com/contact" target="_blank"><b>here</b></a> or drop an email at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a> for more information<br><br></p>
					</div>
				</div>
				<div class="mo-saml-bootstrap-col-md-4 mo-saml-bootstrap-mt-5">
					<div class="plan-box">
						<div class="plan-box-up">
							<i class="fa fa-university fa-3x"><span class="mo-saml-bootstrap-h3">&nbsp;&nbsp;Bank Transfer</span></i>
						</div>
						<p>Please contact us <a href="https://www.miniorange.com/contact" target="_blank"><b>here</b></a> or drop an email at <a href="mailto:samlsupport@xecurify.com"><b>samlsupport@xecurify.com</b></a> so that we can provide you the bank details.<br><br></p>
					</div>
				</div>
			</div>
			<br>
			<h2 class="plan-head-saml saml-scroll" id="upgrade-steps">Steps to upgrade to Premium</h2>
			<br>
			<section class="section-steps mo-saml-bootstrap-ms-4 mo-saml-bootstrap-me-3" id="section-steps">
				<div class="mo-saml-bootstrap-row">
					<div class="mo-saml-bootstrap-col span-1-of-2 steps-box">
						<div class="works-step">
							<div>1</div>
							<p class="saml-text">
								Click on Upgrade Now button of the required licensing plan. You will be redirected to <b>miniOrange Login Console</b>. Enter your password with which you created an account with us. After that you will be redirected to payment page.
							</p>
						</div>
						<br>
						<div class="works-step">
							<div>2</div>
							<p class="saml-text">
								Enter your card details and complete the payment. On successful payment completion, you will see the link to download the premium plugin.
							</p>
						</div>
					</div>
					<div class="mo-saml-bootstrap-col span-1-of-2 steps-box">
						<div class="works-step">
							<div>3</div>
							<p class="saml-text">
								To install the premium plugin, first deactivate and delete the free version of the plugin. Enable the "Keep Configuration Intact" checkbox before deactivating the plugin. By doing so, your saved configurations of the plugin will not get lost.
							</p>
						</div>
						<br>
						<div class="works-step">
							<div>4</div>
							<p class="saml-text">
								From this point on, do not update the premium plugin from the WordPress store.
							</p>
						</div>
					</div>
				</div>
			</section>
		</div>
	</div>
	<form style="display:none;" id="loginform" action="<?php echo esc_url( mo_saml_options_plugin_constants::HOSTNAME . '/moas/login' ); ?>" target="_blank" method="post">
		<input type="email" name="username" value="<?php echo esc_attr( get_option( mo_saml_customer_constants::ADMIN_EMAIL ) ); ?>" />
		<input type="text" name="redirectUrl" value="<?php echo esc_url( mo_saml_options_plugin_constants::HOSTNAME . '/moas/initializepayment' ); ?>" />
		<input type="text" name="requestOrigin" id="requestOrigin" />
	</form>
	<a id="mobacktoaccountsetup" style="display:none;" href="<?php echo esc_url( mo_saml_add_query_arg( array( 'tab' => 'account-setup' ), $server_url ) ); ?>"><?php esc_html_e( 'Back', 'miniorange-saml-20-single-sign-on' ); ?></a>
	<script>
		function upgradeform(planType) {
			jQuery('#requestOrigin').val(planType);
			if (jQuery('#mo_customer_registered').val() == 1)
				jQuery('#loginform').submit();
			else {
				location.href = jQuery('#mobacktoaccountsetup').attr('href');
			}
		}
	</script>
	<?php
}
