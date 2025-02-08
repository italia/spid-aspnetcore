using Microsoft.Extensions.Configuration;
using SPID.AspNetCore.Authentication.Models;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication.Helpers
{
    internal static class OptionsHelper
    {
        internal static SpidConfiguration CreateFromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection("Spid");
            var options = new SpidConfiguration
            {
                IsStagingValidatorEnabled = section.GetValue<bool?>("IsStagingValidatorEnabled") ?? false,
                IsLocalValidatorEnabled = section.GetValue<bool?>("IsLocalValidatorEnabled") ?? false,
                AllowUnsolicitedLogins = section.GetValue<bool?>("AllowUnsolicitedLogins") ?? false,
                AssertionConsumerServiceURL = section.GetValue<string>("AssertionConsumerServiceURL"),
                AssertionConsumerServiceIndex = section.GetValue<ushort?>("AssertionConsumerServiceIndex"),
                AttributeConsumingServiceIndex = section.GetValue<ushort?>("AttributeConsumingServiceIndex") ?? 0,
                CallbackPath = section.GetValue<string>("CallbackPath"),
                IdPRegistryURL = section.GetValue<string>("IdPRegistryURL"),
                EntityId = section.GetValue<string>("EntityId"),
                RemoteSignOutPath = section.GetValue<string>("RemoteSignOutPath"),
                SignOutScheme = section.GetValue<string>("SignOutScheme"),
                UseTokenLifetime = section.GetValue<bool?>("UseTokenLifetime") ?? false,
                SkipUnrecognizedRequests = section.GetValue<bool?>("SkipUnrecognizedRequests") ?? true,
                CacheIdpMetadata = section.GetValue<bool?>("CacheIdpMetadata") ?? true,
                IdpMetadataCacheDurationInMinutes = section.GetValue<int?>("IdpMetadataCacheDurationInMinutes") ?? 1440,
                RandomIdentityProvidersOrder = section.GetValue<bool?>("RandomIdentityProvidersOrder") ?? false,
                SecurityLevel = section.GetValue<int?>("SecurityLevel") ?? 2
            };
            var requestMethodParsed = Enum.TryParse<RequestMethod>(section.GetValue<string?>("RequestMethod"), out var requestMethod);
            options.RequestMethod = requestMethodParsed ? requestMethod : RequestMethod.Post;
            options.DefaultLanguage = section.GetValue<string?>("DefaultLanguage") ?? "it";

            var identityProviders = section
                .GetSection("Providers")
                .GetChildren()
                .ToList()
                .Select(x => new IdentityProvider
                {
                    EntityId = x.GetValue<string>("EntityId"),
                    Name = x.GetValue<string>("Name"),
                    OrganizationDisplayName = x.GetValue<string>("OrganizationDisplayName"),
                    OrganizationLogoUrl = x.GetValue<string>("OrganizationLogoUrl"),
                    OrganizationName = x.GetValue<string>("OrganizationName"),
                    ProviderType = x.GetValue<ProviderType>("Type"),
                    SingleSignOnServiceUrlPost = x.GetValue<string>("SingleSignOnServiceUrlPost"),
                    SingleSignOutServiceUrlPost = x.GetValue<string>("SingleSignOutServiceUrlPost"),
                    SingleSignOnServiceUrlRedirect = x.GetValue<string>("SingleSignOnServiceUrlRedirect"),
                    SingleSignOutServiceUrlRedirect = x.GetValue<string>("SingleSignOutServiceUrlRedirect"),
                    SubjectNameIdRemoveText = x.GetValue<string>("SubjectNameIdRemoveText"),
                    AttributeConsumingServiceIndex = x.GetValue<ushort?>("AttributeConsumingServiceIndex")
                        ?? options.AttributeConsumingServiceIndex,
                    X509SigningCertificates = new System.Collections.Generic.List<string>() { x.GetValue<string>("X509SigningCertificate") }
                }).ToList();
            var eidasSection = configuration.GetSection("Eidas");
            if (eidasSection.Exists())
            {
                identityProviders.Add(new IdentityProvider
                {
                    EntityId = eidasSection.GetValue<string>("EntityId"),
                    Name = eidasSection.GetValue<string>("Name"),
                    OrganizationDisplayName = eidasSection.GetValue<string>("OrganizationDisplayName"),
                    OrganizationLogoUrl = eidasSection.GetValue<string>("OrganizationLogoUrl"),
                    OrganizationName = eidasSection.GetValue<string>("OrganizationName"),
                    ProviderType = ProviderType.StandaloneProvider,
                    SingleSignOnServiceUrlPost = eidasSection.GetValue<string>("SingleSignOnServiceUrlPost"),
                    SingleSignOutServiceUrlPost = eidasSection.GetValue<string>("SingleSignOutServiceUrlPost"),
                    SingleSignOnServiceUrlRedirect = eidasSection.GetValue<string>("SingleSignOnServiceUrlRedirect"),
                    SingleSignOutServiceUrlRedirect = eidasSection.GetValue<string>("SingleSignOutServiceUrlRedirect"),
                    SubjectNameIdRemoveText = eidasSection.GetValue<string>("SubjectNameIdRemoveText"),
                    AttributeConsumingServiceIndex = eidasSection.GetValue<ushort?>("AttributeConsumingServiceIndex")
                        ?? options.AttributeConsumingServiceIndex,
                    X509SigningCertificates = new System.Collections.Generic.List<string>() { eidasSection.GetValue<string>("X509SigningCertificate") }
                });
            }
            options.AddIdentityProviders(identityProviders);

            var certificateSection = section.GetSection("Certificate");
            if (certificateSection.Exists())
            {
                var certificateSource = certificateSection.GetValue<string>("Source");
                if (certificateSource.Equals("Store", System.StringComparison.OrdinalIgnoreCase))
                {
                    var storeConfiguration = certificateSection.GetSection("Store");
                    var location = storeConfiguration.GetValue<StoreLocation>("Location");
                    var name = storeConfiguration.GetValue<StoreName>("Name");
                    var findType = storeConfiguration.GetValue<X509FindType>("FindType");
                    var findValue = storeConfiguration.GetValue<string>("FindValue");
                    var validOnly = storeConfiguration.GetValue<bool>("validOnly");
                    options.Certificate = X509Helpers.GetCertificateFromStore(
                                        location,
                                        name,
                                        findType,
                                        findValue,
                                        validOnly);
                }
                else if (certificateSource.Equals("File", System.StringComparison.OrdinalIgnoreCase))
                {
                    var storeConfiguration = certificateSection.GetSection("File");
                    var path = storeConfiguration.GetValue<string>("Path");
                    var password = storeConfiguration.GetValue<string>("Password");
                    options.Certificate = X509Helpers.GetCertificateFromFile(path, password);
                }
                else if (certificateSource.Equals("Raw", System.StringComparison.OrdinalIgnoreCase))
                {
                    var storeConfiguration = certificateSection.GetSection("Raw");
                    var certificate = storeConfiguration.GetValue<string>("Certificate");
                    var key = storeConfiguration.GetValue<string>("Password");
                    options.Certificate = X509Helpers.GetCertificateFromStrings(certificate, key);
                }
            }
            return options;
        }

        internal static void LoadFromConfiguration(SpidConfiguration options, IConfiguration configuration)
        {
            var createdOptions = CreateFromConfiguration(configuration);
            options.AddIdentityProviders(createdOptions.IdentityProviders);
            options.AllowUnsolicitedLogins = createdOptions.AllowUnsolicitedLogins;
            options.AssertionConsumerServiceURL = createdOptions.AssertionConsumerServiceURL;
            options.AssertionConsumerServiceIndex = createdOptions.AssertionConsumerServiceIndex;
            options.AttributeConsumingServiceIndex = createdOptions.AttributeConsumingServiceIndex;
            options.CallbackPath = createdOptions.CallbackPath;
            options.Certificate = createdOptions.Certificate;
            options.EntityId = createdOptions.EntityId;
            options.IsLocalValidatorEnabled = createdOptions.IsLocalValidatorEnabled;
            options.IsStagingValidatorEnabled = createdOptions.IsStagingValidatorEnabled;
            options.RemoteSignOutPath = createdOptions.RemoteSignOutPath;
            options.SignOutScheme = createdOptions.SignOutScheme;
            options.SkipUnrecognizedRequests = createdOptions.SkipUnrecognizedRequests;
            options.UseTokenLifetime = createdOptions.UseTokenLifetime;
            options.RandomIdentityProvidersOrder = createdOptions.RandomIdentityProvidersOrder;
            options.IdPRegistryURL = createdOptions.IdPRegistryURL;
            options.RequestMethod = createdOptions.RequestMethod;
            options.DefaultLanguage = createdOptions.DefaultLanguage;
        }
    }
}
