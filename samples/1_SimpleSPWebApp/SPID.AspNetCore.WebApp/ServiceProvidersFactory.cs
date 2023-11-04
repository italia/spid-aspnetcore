using Microsoft.Extensions.Options;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Models.ServiceProviders;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SPID.AspNetCore.WebApp
{
    public class ServiceProvidersFactory : IServiceProvidersFactory
    {
        private readonly SpidOptions _options;

        public ServiceProvidersFactory(IOptionsMonitor<SpidOptions> options)
        {
            _options = options.CurrentValue;
        }

        public Task<List<ServiceProvider>> GetServiceProviders()
            => Task.FromResult(new List<ServiceProvider>() {
                new Authentication.Models.ServiceProviders.ServiceProviderPublicFullAggregator()
                {
                    FileName = "metadata2.xml",
                    Certificate = _options.Certificate,
                    Id = Guid.NewGuid(),
                    AggregatorEntityId = "spid.aspnetcore.it",
                    AggregatedEntityId = "TEST",
                    SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                        new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                        }
                    },
                    AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                        new AssertionConsumerService(){
                            Index = 0,
                            IsDefault = true,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.POST
                        },
                        new AssertionConsumerService() {
                            Index = 1,
                            IsDefault = false,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.Redirect
                        }
                    },
                    AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
                        new AttributeConsumingService() {
                            Index = 0,
                            ServiceName = "Service 1",
                            ServiceDescription = "Service 1",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        },
                        new AttributeConsumingService() {
                            Index = 1,
                            ServiceName = "Service 2",
                            ServiceDescription = "Service 2",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        }
                    },
                    OrganizationName = "Organizzazione fittizia per il collaudo",
                    OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
                    OrganizationURL = "https://spid.aspnetcore.it",
                    AggregatorVatNumber = "IT01234567890",
                    AggregatorCompany = "AspNetCore Remote Authenticator for SPID",
                    AggregatorEmailAddress = "info@spid.aspnetcore.it",
                    AggregatorTelephoneNumber = "+3901234567890",
                    AggregatedIPACode = "__aggrsint"
                },
                new Authentication.Models.ServiceProviders.ServiceProviderPrivateFullAggregator()
                {
                    FileName = "metadata3.xml",
                    Certificate = _options.Certificate,
                    Id = Guid.NewGuid(),
                    AggregatorEntityId = "spid.aspnetcore.it",
                    AggregatedEntityId = "TEST",
                    SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                        new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                        }
                    },
                    AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                        new AssertionConsumerService(){
                            Index = 0,
                            IsDefault = true,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.POST
                        },
                        new AssertionConsumerService() {
                            Index = 1,
                            IsDefault = false,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.Redirect
                        }
                    },
                    AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
                        new AttributeConsumingService(){
                            Index = 0,
                            ServiceName = "Service 1",
                            ServiceDescription = "Service 1",
                            ClaimTypes = new SpidClaimTypes[]{
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        },
                        new AttributeConsumingService() {
                            Index = 1,
                            ServiceName = "Service 2",
                            ServiceDescription = "Service 2",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        }
                    },
                    OrganizationName = "Organizzazione fittizia per il collaudo",
                    OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
                    OrganizationURL = "https://spid.aspnetcore.it/",
                    AggregatorVatNumber = "IT01234567890",
                    AggregatorCompany = "AspNetCore Remote Authenticator for SPID",
                    AggregatorEmailAddress = "info@spid.aspnetcore.it",
                    AggregatorTelephoneNumber = "+3901234567890",
                    AggregatedCompany = "Organizzazione fittizia per il collaudo",
                    AggregatedVatNumber = "IT01234567890",
                    BillingCompany = "Billing company",
                    BillingEmailAddress = "billing@email.com",
                    BillingTelephoneNumber = "+3901234567890",
                    CessionarioCommittenteIdCodice = "+390123456789",
                    CessionarioCommittenteIdPaese = "IT",
                    CessionarioCommittenteDenominazione = "Azienda_Destinataria_Fatturazione",
                    CessionarioCommittenteCAP = "12345",
                    CessionarioCommittenteComune = "Comune",
                    CessionarioCommittenteIndirizzo = "Indirizzo",
                    CessionarioCommittenteNazione = "Nazione",
                    CessionarioCommittenteNumeroCivico = "17",
                    CessionarioCommittenteProvincia = "XX"
                },
                new Authentication.Models.ServiceProviders.ServiceProviderPublicLightAggregator()
                {
                    FileName = "metadata4.xml",
                    Certificate = _options.Certificate,
                    Id = Guid.NewGuid(),
                    AggregatorEntityId = "spid.aspnetcore.it",
                    AggregatedEntityId = "TEST",
                    SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                        new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                        }
                    },
                    AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                        new AssertionConsumerService(){
                            Index = 0,
                            IsDefault = true,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.POST
                        },
                        new AssertionConsumerService() {
                            Index = 1,
                            IsDefault = false,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.Redirect
                        }
                    },
                    AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
                        new AttributeConsumingService() {
                            Index = 0,
                            ServiceName = "Service 1",
                            ServiceDescription = "Service 1",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        },
                        new AttributeConsumingService() {
                            Index = 1,
                            ServiceName = "Service 2",
                            ServiceDescription = "Service 2",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        }
                    },
                    OrganizationName = "Organizzazione fittizia per il collaudo",
                    OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
                    OrganizationURL = "https://spid.aspnetcore.it/",
                    AggregatorVatNumber = "IT01234567890",
                    AggregatorCompany = "AspNetCore Remote Authenticator for SPID",
                    AggregatorEmailAddress = "info@spid.aspnetcore.it",
                    AggregatorTelephoneNumber = "+3901234567890",
                    AggregatedIPACode = "__aggrsint"
                },
                new Authentication.Models.ServiceProviders.ServiceProviderPrivateLightAggregator()
                {
                    FileName = "metadata5.xml",
                    Certificate = _options.Certificate,
                    Id = Guid.NewGuid(),
                    AggregatorEntityId = "spid.aspnetcore.it",
                    AggregatedEntityId = "TEST",
                    SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                        new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                        }
                    },
                    AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                        new AssertionConsumerService(){
                            Index = 0,
                            IsDefault = true,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.POST
                        },
                        new AssertionConsumerService() {
                            Index = 1,
                            IsDefault = false,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.Redirect
                        }
                    },
                    AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
                        new AttributeConsumingService(){
                            Index = 0,
                            ServiceName = "Service 1",
                            ServiceDescription = "Service 1",
                            ClaimTypes = new SpidClaimTypes[]{
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        },
                        new AttributeConsumingService() {
                            Index = 1,
                            ServiceName = "Service 2",
                            ServiceDescription = "Service 2",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        }
                    },
                    OrganizationName = "Organizzazione fittizia per il collaudo",
                    OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
                    OrganizationURL = "https://spid.aspnetcore.it/",
                    AggregatorVatNumber = "IT01234567890",
                    AggregatorCompany = "AspNetCore Remote Authenticator for SPID",
                    AggregatorEmailAddress = "info@spid.aspnetcore.it",
                    AggregatorTelephoneNumber = "+3901234567890",
                    AggregatedCompany = "Organizzazione fittizia per il collaudo",
                    AggregatedVatNumber = "IT01234567890",
                    BillingCompany = "Billing company",
                    BillingEmailAddress = "billing@email.com",
                    BillingTelephoneNumber = "+3901234567890",
                    CessionarioCommittenteIdCodice = "+390123456789",
                    CessionarioCommittenteIdPaese = "IT",
                    CessionarioCommittenteDenominazione = "Azienda_Destinataria_Fatturazione",
                    CessionarioCommittenteCAP = "12345",
                    CessionarioCommittenteComune = "Comune",
                    CessionarioCommittenteIndirizzo = "Indirizzo",
                    CessionarioCommittenteNazione = "Nazione",
                    CessionarioCommittenteNumeroCivico = "17",
                    CessionarioCommittenteProvincia = "XX"
                },
                new Authentication.Models.ServiceProviders.ServiceProviderPublicFullOperator()
                {
                    FileName = "metadata6.xml",
                    Certificate = _options.Certificate,
                    Id = Guid.NewGuid(),
                    AggregatorEntityId = "spid.aspnetcore.it",
                    AggregatedEntityId = "TEST",
                    SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                        new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                        }
                    },
                    AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                        new AssertionConsumerService(){
                            Index = 0,
                            IsDefault = true,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.POST
                        },
                        new AssertionConsumerService() {
                            Index = 1,
                            IsDefault = false,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.Redirect
                        }
                    },
                    AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
                        new AttributeConsumingService() {
                            Index = 0,
                            ServiceName = "Service 1",
                            ServiceDescription = "Service 1",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        },
                        new AttributeConsumingService() {
                            Index = 1,
                            ServiceName = "Service 2",
                            ServiceDescription = "Service 2",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        }
                    },
                    OrganizationName = "Organizzazione fittizia per il collaudo",
                    OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
                    OrganizationURL = "https://spid.aspnetcore.it/",
                    OperatorVatNumber = "IT01234567890",
                    OperatorCompany = "Organizzazione fittizia per il collaudo",
                    OperatorEmailAddress = "info@test.it",
                    OperatorTelephoneNumber = "+3901234567890",
                    OperatorIPACode = "__aggrsint",
                    OperatorFiscalCode = "01261280620"
                },
                new Authentication.Models.ServiceProviders.ServiceProviderPublicLightOperator()
                {
                    FileName = "metadata7.xml",
                    Certificate = _options.Certificate,
                    Id = Guid.NewGuid(),
                    AggregatorEntityId = "spid.aspnetcore.it",
                    AggregatedEntityId = "TEST",
                    SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                        new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                        }
                    },
                    AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                        new AssertionConsumerService(){
                            Index = 0,
                            IsDefault = true,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.POST
                        },
                        new AssertionConsumerService() {
                            Index = 1,
                            IsDefault = false,
                            Location = "https://localhost:5001/signin-spid",
                            ProtocolBinding = ProtocolBinding.Redirect
                        }
                    },
                    AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
                        new AttributeConsumingService() {
                            Index = 0,
                            ServiceName = "Service 1",
                            ServiceDescription = "Service 1",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        },
                        new AttributeConsumingService() {
                            Index = 1,
                            ServiceName = "Service 2",
                            ServiceDescription = "Service 2",
                            ClaimTypes = new SpidClaimTypes[] {
                                SpidClaimTypes.Name,
                                SpidClaimTypes.FamilyName,
                                SpidClaimTypes.FiscalNumber,
                                SpidClaimTypes.Email
                            }
                        }
                    },
                    OrganizationName = "Organizzazione fittizia per il collaudo",
                    OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
                    OrganizationURL = "https://spid.aspnetcore.it/",
                    OperatorVatNumber = "IT01234567890",
                    OperatorCompany = "Organizzazione fittizia per il collaudo",
                    OperatorEmailAddress = "info@test.it",
                    OperatorTelephoneNumber = "+3901234567890",
                    OperatorIPACode = "__aggrsint",
                    OperatorFiscalCode = "01234567890",
                    AggregatedIPACode = "__aggrsint"
                }});
    }
}
