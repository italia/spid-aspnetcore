using IdentityServer4;
using IdentityServer4.Models;
using SPID.AspNetCore.Authentication.Models;
using System.Collections.Generic;

namespace SPID.AspNetCore.IdentityServerSample.IdentityServer
{
    public class SpidIdentityResource : IdentityResource
    {
        public SpidIdentityResource()
        {
            base.Name = "spid";
            base.DisplayName = "Spid claims";
            base.Description = "Information from Spid claims";
            base.Emphasize = true;
            base.UserClaims = new List<string>()
            {
                SpidClaimTypes.Name.Value,
                SpidClaimTypes.Email.Value,
                SpidClaimTypes.FamilyName.Value,
                SpidClaimTypes.FiscalNumber.Value,
                SpidClaimTypes.RawFiscalNumber.Value,
                SpidClaimTypes.Mail.Value,
                SpidClaimTypes.Address.Value,
                SpidClaimTypes.CompanyName.Value,
                SpidClaimTypes.CountyOfBirth.Value,
                SpidClaimTypes.DateOfBirth.Value,
                SpidClaimTypes.DigitalAddress.Value,
                SpidClaimTypes.ExpirationDate.Value,
                SpidClaimTypes.Gender.Value,
                SpidClaimTypes.IdCard.Value,
                SpidClaimTypes.IvaCode.Value,
                SpidClaimTypes.MobilePhone.Value,
                SpidClaimTypes.PlaceOfBirth.Value,
                SpidClaimTypes.RegisteredOffice.Value,
                SpidClaimTypes.SpidCode.Value,
                SpidClaimTypes.CompanyFiscalNumber.Value,
                SpidClaimTypes.DomicileStreetAddress.Value,
                SpidClaimTypes.DomicilePostalCode.Value,
                SpidClaimTypes.DomicileMunicipality.Value,
                SpidClaimTypes.DomicileProvince.Value,
                SpidClaimTypes.DomicileNation.Value,
            };
        }
    }

    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new SpidIdentityResource()
            };

        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                // interactive ASP.NET Core MVC client
                new Client
                {
                    ClientId = "mvc",
                    ClientSecrets = { new Secret("secret".Sha256()) },
                    AlwaysIncludeUserClaimsInIdToken = true,
                    AllowedGrantTypes = GrantTypes.Code,
                    
                    // where to redirect to after login
                    RedirectUris = { "https://localhost:5002/signin-oidc" },

                    // where to redirect to after logout
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "spid"
                    }
                }
            };
    }
}