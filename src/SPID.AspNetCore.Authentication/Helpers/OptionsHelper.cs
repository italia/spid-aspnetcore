﻿using Microsoft.Extensions.Configuration;
using SPID.AspNetCore.Authentication.Models;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication.Helpers
{
    internal static class OptionsHelper
    {
        internal static SpidConfiguration CreateFromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection("Spid");
            var options = new SpidConfiguration();

            options.IsStagingValidatorEnabled = section.GetValue<bool?>("IsStagingValidatorEnabled") ?? false;
            options.IsLocalValidatorEnabled = section.GetValue<bool?>("IsLocalValidatorEnabled") ?? false;
            options.AllowUnsolicitedLogins = section.GetValue<bool?>("AllowUnsolicitedLogins") ?? false;
            options.AssertionConsumerServiceURL = section.GetValue<string>("AssertionConsumerServiceURL");
            options.AssertionConsumerServiceIndex = section.GetValue<ushort?>("AssertionConsumerServiceIndex");
            options.AttributeConsumingServiceIndex = section.GetValue<ushort?>("AttributeConsumingServiceIndex") ?? 0;
            options.CallbackPath = section.GetValue<string>("CallbackPath");
            options.EntityId = section.GetValue<string>("EntityId");
            options.RemoteSignOutPath = section.GetValue<string>("RemoteSignOutPath");
            options.SignOutScheme = section.GetValue<string>("SignOutScheme");
            options.UseTokenLifetime = section.GetValue<bool?>("UseTokenLifetime") ?? false;
            options.SkipUnrecognizedRequests = section.GetValue<bool?>("SkipUnrecognizedRequests") ?? true;
            options.CacheIdpMetadata = section.GetValue<bool?>("CacheIdpMetadata") ?? false;
            options.RandomIdentityProvidersOrder = section.GetValue<bool?>("RandomIdentityProvidersOrder") ?? false;
            options.SecurityLevel = section.GetValue<int?>("SecurityLevel") ?? 2;

            var identityProviders = section
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
                    SecurityLevel = x.GetValue<int?>("SecurityLevel") ?? 2,
                    AttributeConsumingServiceIndex = x.GetValue<ushort?>("AttributeConsumingServiceIndex")
                        ?? options.AttributeConsumingServiceIndex
                }).ToList();
            var eidasSection = configuration.GetSection("Eidas");
            if (eidasSection.Exists())
            {
                identityProviders.Add(new IdentityProvider
                {
                    Method = eidasSection.GetValue<RequestMethod>("Method"),
                    Name = eidasSection.GetValue<string>("Name"),
                    OrganizationDisplayName = eidasSection.GetValue<string>("OrganizationDisplayName"),
                    OrganizationLogoUrl = eidasSection.GetValue<string>("OrganizationLogoUrl"),
                    OrganizationName = eidasSection.GetValue<string>("OrganizationName"),
                    OrganizationUrl = eidasSection.GetValue<string>("OrganizationUrl"),
                    OrganizationUrlMetadata = eidasSection.GetValue<string>("OrganizationUrlMetadata"),
                    ProviderType = ProviderType.StandaloneProvider,
                    SingleSignOnServiceUrl = eidasSection.GetValue<string>("SingleSignOnServiceUrl"),
                    SingleSignOutServiceUrl = eidasSection.GetValue<string>("SingleSignOutServiceUrl"),
                    SubjectNameIdRemoveText = eidasSection.GetValue<string>("SubjectNameIdRemoveText"),
                    SecurityLevel = eidasSection.GetValue<int?>("SecurityLevel") ?? 2,
                    AttributeConsumingServiceIndex = eidasSection.GetValue<ushort?>("AttributeConsumingServiceIndex")
                        ?? options.AttributeConsumingServiceIndex
                });
            }
            options.AddIdentityProviders(identityProviders);

            var certificateSection = section.GetSection("Certificate");
            if (certificateSection != null)
            {
                var certificateSource = certificateSection.GetValue<CertificateSource>("Source");
                if (certificateSource == CertificateSource.Store)
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
                else if (certificateSource == CertificateSource.File)
                {
                    var storeConfiguration = certificateSection.GetSection("File");
                    var path = storeConfiguration.GetValue<string>("Path");
                    var password = storeConfiguration.GetValue<string>("Password");
                    options.Certificate = X509Helpers.GetCertificateFromFile(path, password);
                }
                else if (certificateSource == CertificateSource.Raw)
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
        }
    }
}
