using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Events;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication
{
    public class SpidOptions : RemoteAuthenticationOptions
    {
        public SpidOptions()
        {
            CallbackPath = "/signin-spid";
            // In ADFS the cleanup messages are sent to the same callback path as the initial login.
            // In AAD it sends the cleanup message to a random Reply Url and there's no deterministic way to configure it.
            //  If you manage to get it configured, then you can set RemoteSignOutPath accordingly.
            RemoteSignOutPath = "/signout-spid";
            Events = new SpidEvents();
        }

        /// <summary>
        /// Check that the options are valid.  Should throw an exception if things are not ok.
        /// </summary>
        public override void Validate()
        {
            base.Validate();

        }


        /// <summary>
        ///  Requests received on this path will cause the handler to invoke SignOut using the SignOutScheme.
        /// </summary>
        public PathString RemoteSignOutPath { get; set; }

        /// <summary>
        /// Indicates if requests to the CallbackPath may also be for other components. If enabled the handler will pass
        /// requests through that do not contain Spid authentication responses. Disabling this and setting the
        /// CallbackPath to a dedicated endpoint may provide better error handling.
        /// This is disabled by default.
        /// </summary>
        public bool SkipUnrecognizedRequests { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SpidEvents"/> to call when processing Spid messages.
        /// </summary>
        public new SpidEvents Events
        {
            get => (SpidEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Indicates that the authentication session lifetime (e.g. cookies) should match that of the authentication token.
        /// If the token does not provide lifetime information then normal session lifetimes will be used.
        /// This is enabled by default.
        /// </summary>
        public bool UseTokenLifetime { get; set; } = true;

        /// <summary>
        /// The Ws-Federation protocol allows the user to initiate logins without contacting the application for a Challenge first.
        /// However, that flow is susceptible to XSRF and other attacks so it is disabled here by default.
        /// </summary>
        public bool AllowUnsolicitedLogins { get; set; }

        /// <summary>
        /// The Authentication Scheme to use with SignOutAsync from RemoteSignOutPath. SignInScheme will be used if this
        /// is not set.
        /// </summary>
        public string SignOutScheme { get; set; }

        /// <summary>
        /// Gets or sets the entity identifier.
        /// </summary>
        /// <value>
        /// The entity identifier.
        /// </value>
        public string EntityId { get; set; }

        /// <summary>
        /// Gets or sets the index of the assertion consumer service.
        /// </summary>
        /// <value>
        /// The index of the assertion consumer service.
        /// </value>
        public string AssertionConsumerServiceIndex { get; set; }

        /// <summary>
        /// Gets the identity providers.
        /// </summary>
        /// <value>
        /// The identity providers.
        /// </value>
        public IEnumerable<IdentityProvider> IdentityProviders { get; } = new List<IdentityProvider>() {
            new IdentityProvider() {
                Name = "Aruba",
                OrganizationName = "ArubaPEC S.p.A.",
                OrganizationDisplayName = "ArubaPEC S.p.A.",
                OrganizationUrlMetadata = "https://loginspid.aruba.it/metadata",
                OrganizationUrl = "https://www.pec.it/",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-arubaid.png",
                SingleSignOnServiceUrl = "https://loginspid.aruba.it/ServiceLoginWelcome",
                SingleSignOutServiceUrl = "https://loginspid.aruba.it/ServiceLogoutRequest",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Poste",
                OrganizationName = "Poste Italiane SpA",
                OrganizationDisplayName = "Poste Italiane SpA",
                OrganizationUrlMetadata = "https://posteid.poste.it/jod-fs/metadata/metadata.xml",
                OrganizationUrl = "https://www.poste.it",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-posteid.png",
                SingleSignOnServiceUrl = "https://posteid.poste.it/jod-fs/ssoservicepost",
                SingleSignOutServiceUrl = "https://posteid.poste.it/jod-fs/sloservicepost",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Intesa",
                OrganizationName = "IN.TE.S.A. S.p.A.",
                OrganizationDisplayName = "IN.TE.S.A. S.p.A.",
                OrganizationUrlMetadata = "https://spid.intesa.it/metadata/metadata.xml",
                OrganizationUrl = "https://www.intesa.it/",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-intesaid.png",
                SingleSignOnServiceUrl = "https://spid.intesa.it/Time4UserServices/services/idp/AuthnRequest/",
                SingleSignOutServiceUrl = "https://spid.intesa.it/Time4UserServices/services/idp/SingleLogout",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Infocert",
                OrganizationName = "InfoCert S.p.A.",
                OrganizationDisplayName = "InfoCert S.p.A.",
                OrganizationUrlMetadata = "https://identity.infocert.it/metadata/metadata.xml",
                OrganizationUrl = "https://www.infocert.it",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-infocertid.png",
                SingleSignOnServiceUrl = "https://identity.infocert.it/spid/samlsso",
                SingleSignOutServiceUrl = "https://identity.infocert.it/spid/samlslo",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Lepida",
                OrganizationName = "Lepida S.p.A.",
                OrganizationDisplayName = "Lepida S.p.A.",
                OrganizationUrlMetadata = "https://id.lepida.it/idp/shibboleth",
                OrganizationUrl = "https://www.lepida.it",
                OrganizationLogoUrl = "https://id.lepida.it/idm/app/pubblica/lepida_spid.png",
                SingleSignOnServiceUrl = "https://id.lepida.it/idp/profile/SAML2/POST/SSO",
                SingleSignOutServiceUrl = "https://id.lepida.it/idp/profile/SAML2/POST/SLO",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Namirial",
                OrganizationName = "Namirial S.p.a.",
                OrganizationDisplayName = "Namirial S.p.a.",
                OrganizationUrlMetadata = "https://idp.namirialtsp.com/idp/metadata",
                OrganizationUrl = "https://www.namirialtsp.com",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-namirialid.png",
                SingleSignOnServiceUrl = "https://idp.namirialtsp.com/idp/profile/SAML2/POST/SSO",
                SingleSignOutServiceUrl = "https://idp.namirialtsp.com/idp/profile/SAML2/POST/SLO",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Register",
                OrganizationName = "Register.it S.p.A.",
                OrganizationDisplayName = "Register.it S.p.A.",
                OrganizationUrlMetadata = "https://spid.register.it/login/metadata",
                OrganizationUrl = "https//www.register.it",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-spiditalia.png",
                SingleSignOnServiceUrl = "https://spid.register.it/login/sso",
                SingleSignOutServiceUrl = "https://spid.register.it/login/singleLogout",
                Method = "Post"
            },
            new IdentityProvider() {
                Name = "Sielte",
                OrganizationName = "Sielte S.p.A.",
                OrganizationDisplayName = "Sielte S.p.A.",
                OrganizationUrlMetadata = "https://identity.sieltecloud.it/simplesaml/metadata.xml",
                OrganizationUrl = "http://www.sielte.it",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-sielteid.png",
                SingleSignOnServiceUrl = "https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php",
                SingleSignOutServiceUrl = "https://identity.sieltecloud.it/simplesaml/saml2/idp/SLO.php",
                Method = "Post",
                NowDelta = "-2"
            },
            new IdentityProvider() {
                Name = "Tim	TI",
                OrganizationName = "Trust Technologies srl",
                OrganizationDisplayName = "Trust Technologies srl",
                OrganizationUrlMetadata = "https://login.id.tim.it/spid-services/MetadataBrowser/idp",
                OrganizationUrl = "https://www.trusttechnologies.it",
                OrganizationLogoUrl = "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-timid.png",
                SingleSignOnServiceUrl = "https://login.id.tim.it/affwebservices/public/saml2sso",
                SingleSignOutServiceUrl = "https://login.id.tim.it/affwebservices/public/saml2slo",
                Method = "Post"
            }
        };

        public bool IsValidatorEnabled
        {
            get
            {
                return IdentityProviders.Any(p => p.Name == "Validator");
            }
            set
            {
                if (value && !IsValidatorEnabled)
                {
                    ((List<IdentityProvider>)IdentityProviders).Add(
                        new IdentityProvider()
                        {
                            Name = "Validator",
                            OrganizationName = "Validator SPID",
                            OrganizationDisplayName = "Validator SPID",
                            OrganizationUrlMetadata = "https://validator.spid.gov.it/metadata.xml",
                            OrganizationUrl = "https://validator.spid.gov.it",
                            OrganizationLogoUrl = "https://validator.spid.gov.it/img/idp-logo.png",
                            SingleSignOnServiceUrl = "https://validator.spid.gov.it/samlsso",
                            SingleSignOutServiceUrl = "https://validator.spid.gov.it/samlsso",
                            Method = "Post"
                        });
                }
            }
        }

        /// <summary>
        /// Gets or sets the certificate.
        /// </summary>
        /// <value>
        /// The certificate.
        /// </value>
        public X509Certificate2 Certificate { get; set; }
    }
}
