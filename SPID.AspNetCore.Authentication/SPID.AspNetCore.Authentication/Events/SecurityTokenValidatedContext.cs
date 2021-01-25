using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Saml;
using System.Security.Claims;

namespace SPID.AspNetCore.Authentication.Events
{
    public class SecurityTokenValidatedContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a <see cref="SecurityTokenValidatedContext"/>
        /// </summary>
        public SecurityTokenValidatedContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, ClaimsPrincipal principal, AuthenticationProperties properties)
            : base(context, scheme, options, properties)
            => Principal = principal;

        /// <summary>
        /// The <see cref="AuthnRequestType"/> received on this request.
        /// </summary>
        public AuthnRequestType ProtocolMessage { get; set; }

        /// <summary>
        /// The <see cref="SecurityToken"/> that was validated.
        /// </summary>
        public SecurityToken SecurityToken { get; set; }
    }
}
