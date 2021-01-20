using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Helpers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication
{
    public class SpidOptions : RemoteAuthenticationOptions
    {
        private readonly List<IdentityProvider> _identityProviders = new();

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
        public ushort AssertionConsumerServiceIndex { get; set; }

        /// <summary>
        /// Gets or sets the index of the attribute consuming service.
        /// </summary>
        /// <value>
        /// The index of the attribute consuming service.
        /// </value>
        public ushort AttributeConsumingServiceIndex { get; set; }

        /// <summary>
        /// Gets the identity providers.
        /// </summary>
        /// <value>
        /// The identity providers.
        /// </value>
        public IEnumerable<IdentityProvider> IdentityProviders 
        { 
            get
            {
                var result = _identityProviders.AsEnumerable();
                if (!IsLocalValidatorEnabled)
                    result = result.Where(c => c.ProviderType != ProviderType.DevelopmentProvider);

                if (!IsStagingValidatorEnabled)
                    result = result.Where(c => c.ProviderType != ProviderType.StagingProvider);

                return result;
            }
        }

        public bool IsStagingValidatorEnabled { get; set; }

        public bool IsLocalValidatorEnabled { get; set; }

        /// <summary>
        /// Gets or sets the certificate.
        /// </summary>
        /// <value>
        /// The certificate.
        /// </value>
        public X509Certificate2 Certificate { get; set; }

        public void AddIdentityProviders(IEnumerable<IdentityProvider> identityProviders)
        {
            _identityProviders.AddRange(identityProviders);
        }

        public void LoadFromConfiguration(IConfigurationSection configuration)
        {
            _identityProviders.AddRange(configuration
                .GetSection("Providers")
                .GetChildren()
                .ToList()
                .Select(x => new IdentityProvider
                {
                    Method = x.GetValue<RequestMethod>("Method"),
                    Name = x.GetValue<string>("Name"),
                    OrganizationDisplayName = x.GetValue<string>("OrganizationDisplayName"),
                    OrganizationLogoUrl = x.GetValue<string>("OrganizationLogoUrl"),
                    OrganizationName = x.GetValue<string>("OrganizationName"),
                    OrganizationUrl = x.GetValue<string>("OrganizationUrl"),
                    OrganizationUrlMetadata = x.GetValue<string>("OrganizationUrlMetadata"),
                    ProviderType = x.GetValue<ProviderType>("Type"),
                    SingleSignOnServiceUrl = x.GetValue<string>("SingleSignOnServiceUrl"),
                    SingleSignOutServiceUrl = x.GetValue<string>("SingleSignOutServiceUrl"),
                    SubjectNameIdRemoveText = x.GetValue<string>("SubjectNameIdRemoveText"),
                    PerformFullResponseValidation = x.GetValue<bool>("PerformFullResponseValidation"),
                }));
            IsStagingValidatorEnabled = configuration.GetValue<bool?>("IsStagingValidatorEnabled") ?? false;
            IsLocalValidatorEnabled = configuration.GetValue<bool?>("IsLocalValidatorEnabled") ?? false;
            AllowUnsolicitedLogins = configuration.GetValue<bool?>("AllowUnsolicitedLogins") ?? false;
            AssertionConsumerServiceIndex = configuration.GetValue<ushort?>("AssertionConsumerServiceIndex") ?? 0;
            AttributeConsumingServiceIndex = configuration.GetValue<ushort?>("AttributeConsumingServiceIndex") ?? 0;
            CallbackPath = configuration.GetValue<string>("CallbackPath") ?? CallbackPath;
            EntityId = configuration.GetValue<string>("EntityId");
            RemoteSignOutPath = configuration.GetValue<string>("RemoteSignOutPath") ?? RemoteSignOutPath;
            SignOutScheme = configuration.GetValue<string>("SignOutScheme");
            UseTokenLifetime = configuration.GetValue<bool?>("UseTokenLifetime") ?? false;
            SkipUnrecognizedRequests = configuration.GetValue<bool?>("SkipUnrecognizedRequests") ?? true;
            var certificateSection = configuration.GetSection("Certificate");
            if (certificateSection != null) 
            {
                var certificateSource = certificateSection.GetValue<string>("Source");
                if (certificateSource == "Store")
                {
                    var storeConfiguration = certificateSection.GetSection("Store");
                    var location = configuration.GetValue<StoreLocation>("Location");
                    var name = configuration.GetValue<StoreName>("Name");
                    var findType = configuration.GetValue<X509FindType>("FindType");
                    var findValue = configuration.GetValue<string>("FindValue");
                    var validOnly = configuration.GetValue<bool>("validOnly");
                    Certificate = X509Helper.GetCertificateFromStore(
                                        StoreLocation.CurrentUser, StoreName.My,
                                        X509FindType.FindBySubjectName,
                                        "HackDevelopers",
                                        validOnly: false);
                }
                else if (certificateSource == "File")
                {
                    var storeConfiguration = certificateSection.GetSection("File");
                    var path = configuration.GetValue<string>("Path");
                    var password = configuration.GetValue<string>("Password");
                    Certificate = X509Helper.GetCertificateFromFile(path, password);
                }
                else
                {
                    var storeConfiguration = certificateSection.GetSection("Raw");
                    var certificate = configuration.GetValue<string>("Certificate");
                    var key = configuration.GetValue<string>("Key");
                    Certificate = X509Helper.GetCertificateFromStrings(certificate, key);
                }
            }
        }
    }
}
