using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication.Models
{
    public sealed class SpidConfiguration
    {
        private readonly List<IdentityProvider> _identityProviders = new();

        /// <summary>
        ///  Requests received on this path will cause the handler to invoke SignIn using the SignInScheme.
        /// </summary>
        public PathString CallbackPath { get; set; }

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
        /// Gets or sets the URL of the assertion consumer service.
        /// </summary>
        /// <value>
        /// The index of the assertion consumer service.
        /// </value>
        public string AssertionConsumerServiceURL { get; set; }

        /// <summary>
        /// Gets or sets the index of the assertion consumer service.
        /// </summary>
        /// <value>
        /// The index of the assertion consumer service.
        /// </value>
        public ushort? AssertionConsumerServiceIndex { get; set; }

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
        public IEnumerable<IdentityProvider> IdentityProviders => _identityProviders;

        public bool RandomIdentityProvidersOrder { get; set; }

        public bool IsStagingValidatorEnabled { get; set; }

        public bool IsLocalValidatorEnabled { get; set; }

        /// <summary>
        /// Gets or sets the certificate.
        /// </summary>
        /// <value>
        /// The certificate.
        /// </value>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether idp metadata should be cached.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [cache idp metadata]; otherwise, <c>false</c>.
        /// </value>
        public bool CacheIdpMetadata { get; set; }

        /// <summary>
        /// Gets or sets the idp metadata cache duration in minutes.
        /// </summary>
        /// <value>
        /// The idp metadata cache duration in minutes.
        /// </value>
        public int IdpMetadataCacheDurationInMinutes { get; set; }

        /// <summary>
        /// Gets or sets the IdentityProviders Registry URL.
        /// </summary>
        /// <value>
        /// The identifier p registry URL.
        /// </value>
        public string IdPRegistryURL { get; set; }

        /// <summary>
        /// Gets or sets the default language.
        /// </summary>
        /// <value>
        /// The default language.
        /// </value>
        public string DefaultLanguage { get; set; }

        /// <summary>
        /// Gets or sets the security level.
        /// </summary>
        /// <value>
        /// The security level.
        /// </value>
        public int SecurityLevel { get; set; }

        /// <summary>
        /// Gets or sets the request method.
        /// </summary>
        /// <value>
        /// The request method.
        /// </value>
        public RequestMethod RequestMethod { get; set; }

        public void AddIdentityProviders(IEnumerable<IdentityProvider> identityProviders)
        {
            _identityProviders.AddRange(identityProviders);
        }
    }
}
