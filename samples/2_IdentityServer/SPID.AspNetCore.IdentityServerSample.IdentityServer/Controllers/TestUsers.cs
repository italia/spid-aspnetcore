using IdentityModel;
using IdentityServer4.Test;
using System.Collections.Generic;
using System.Security.Claims;

namespace SPID.AspNetCore.IdentityServerSample.IdentityServer
{
    public class TestUsers
    {
        public static List<TestUser> Users
        {
            get
            {
                return new List<TestUser>
                {
                    new TestUser
                    {
                        SubjectId = "1",
                        Username = "TestUser1",
                        Password = "TestUser1",
                        Claims =
                        {
                            new Claim(JwtClaimTypes.Name, "TestUser1"),
                            new Claim(JwtClaimTypes.GivenName, "TestUser1"),
                            new Claim(JwtClaimTypes.FamilyName, "TestUser1"),
                            new Claim(JwtClaimTypes.Email, "TestUser1@email.com"),
                            new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        }
                    },
                    new TestUser
                    {
                        SubjectId = "2",
                        Username = "TestUser2",
                        Password = "TestUser2",
                        Claims =
                        {
                            new Claim(JwtClaimTypes.Name, "TestUser2"),
                            new Claim(JwtClaimTypes.GivenName, "TestUser2"),
                            new Claim(JwtClaimTypes.FamilyName, "TestUser2"),
                            new Claim(JwtClaimTypes.Email, "TestUser2@email.com"),
                            new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        }
                    }
                };
            }
        }
    }
}