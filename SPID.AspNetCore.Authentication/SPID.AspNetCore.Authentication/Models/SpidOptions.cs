using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication.Models
{
    public sealed class SpidOptions : RemoteAuthenticationOptions
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

        /// <summary>
        /// Gets or sets a value indicating whether the identity providers order is random or not.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [random identity providers order]; otherwise, <c>false</c>.
        /// </value>
        public bool RandomIdentityProvidersOrder { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the staging validator is enabled.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is staging validator enabled; otherwise, <c>false</c>.
        /// </value>
        public bool IsStagingValidatorEnabled { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the local validator is enabled.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is local validator enabled; otherwise, <c>false</c>.
        /// </value>
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
        /// Gets or sets the type of the principal name claim.
        /// </summary>
        /// <value>
        /// The type of the principal name claim.
        /// </value>
        public SpidClaimTypes PrincipalNameClaimType { get; set; } = SpidClaimTypes.Email;

        public IEnumerable<IdentityProvider> FilteredIdentityProviders
        {
            get
            {
                var result = _identityProviders.AsEnumerable();
                if (!IsLocalValidatorEnabled)
                    result = result.Where(c => c.ProviderType != ProviderType.DevelopmentProvider
                        && c.ProviderType != ProviderType.StandaloneProvider);

                if (!IsStagingValidatorEnabled)
                    result = result.Where(c => c.ProviderType != ProviderType.StagingProvider
                        && c.ProviderType != ProviderType.StandaloneProvider);

                return RandomIdentityProvidersOrder
                    ? result.OrderBy(x => Guid.NewGuid())
                    : result;
            }
        }

        /// <summary>
        /// Adds the identity providers.
        /// </summary>
        /// <param name="identityProviders">The identity providers.</param>
        /// <returns></returns>
        public void AddIdentityProviders(IEnumerable<IdentityProvider> identityProviders)
        {
            _identityProviders.AddRange(identityProviders);
        }

        /// <summary>
        /// Loads from configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        /// <returns></returns>
        public void LoadFromConfiguration(IConfiguration configuration)
        {
            var conf = OptionsHelper.CreateFromConfiguration(configuration);
            _identityProviders.AddRange(conf.IdentityProviders);
            IsStagingValidatorEnabled = conf.IsStagingValidatorEnabled;
            IsLocalValidatorEnabled = conf.IsLocalValidatorEnabled;
            AllowUnsolicitedLogins = conf.AllowUnsolicitedLogins;
            AssertionConsumerServiceURL = conf.AssertionConsumerServiceURL;
            AssertionConsumerServiceIndex = conf.AssertionConsumerServiceIndex;
            AttributeConsumingServiceIndex = conf.AttributeConsumingServiceIndex;
            CallbackPath = conf.CallbackPath.HasValue ? conf.CallbackPath : CallbackPath;
            EntityId = conf.EntityId;
            RemoteSignOutPath = conf.RemoteSignOutPath.HasValue ? conf.RemoteSignOutPath : RemoteSignOutPath;
            SignOutScheme = conf.SignOutScheme;
            UseTokenLifetime = conf.UseTokenLifetime;
            SkipUnrecognizedRequests = conf.SkipUnrecognizedRequests;
            Certificate = conf.Certificate;
            CacheIdpMetadata = conf.CacheIdpMetadata;
            RandomIdentityProvidersOrder = conf.RandomIdentityProvidersOrder;
        }
    }
}
