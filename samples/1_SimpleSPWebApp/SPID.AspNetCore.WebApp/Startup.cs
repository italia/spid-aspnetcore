using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SPID.AspNetCore.Authentication;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Models.ServiceProviders;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SPID.AspNetCore.WebApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }


        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services
                .AddAuthentication(o =>
                {
                    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultChallengeScheme = SpidDefaults.AuthenticationScheme;
                })
                .AddSpid(o =>
                {
                    o.LoadFromConfiguration(Configuration);
                    o.Events.OnTokenCreating = async (s) => await s.HttpContext.RequestServices.GetRequiredService<CustomSpidEvents>().TokenCreating(s);
                    o.ServiceProviders.AddRange(GetServiceProviders(o));
                })
                .AddServiceProvidersFactory<ServiceProvidersFactory>()
                .AddLogHandler<LogHandler>()
                .AddCookie();
            services.AddScoped<CustomSpidEvents>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseDeveloperExceptionPage();
            app.UseHsts();
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.AddSpidSPMetadataEndpoints();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                                    name: "default",
                                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        public class CustomSpidEvents : SpidEvents
        {
            public CustomSpidEvents(IServiceProvider serviceProvider)
            {

            }

            public override Task TokenCreating(SecurityTokenCreatingContext context)
            {
                return base.TokenCreating(context);
            }
        }

        private List<Authentication.Models.ServiceProviders.ServiceProvider> GetServiceProviders(SpidOptions o)
        {
            return new List<Authentication.Models.ServiceProviders.ServiceProvider>(){
                    new Authentication.Models.ServiceProviders.ServiceProviderPublic()
                    {
                        FileName = "metadata.xml",
                        Certificate = o.Certificate,
                        Id = Guid.NewGuid(),
                        EntityId = "https://spid.aspnetcore.it/",
                        SingleLogoutServiceLocations = new List<SingleLogoutService>() {
                            new SingleLogoutService() {
                                Location = "https://localhost:5001/signout-spid",
                                ProtocolBinding = ProtocolBinding.POST
                            }
                        },
                        AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
                            new AssertionConsumerService() {
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
                        VatNumber = "IT01234567890",
                        EmailAddress = "info@aspid.aspnetcore.it",
                        TelephoneNumber = "+3901234567890",
                        IPACode = "__aggrsint"
                    },
                    new Authentication.Models.ServiceProviders.ServiceProviderPrivate()
                    {
                        FileName = "metadata1.xml",
                        Certificate = o.Certificate,
                        Id = Guid.NewGuid(),
                        EntityId = "https://spid.aspnetcore.it/",
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
                        VatNumber = "IT01234567890",
                        Company = "Organizzazione fittizia per il collaudo",
                        EmailAddress = "info@spid.aspnetcore.it",
                        TelephoneNumber = "+3901234567890",
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
                    } };
        }

    }
}
