using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;

namespace SPID.AspNetCore.Authentication.Events
{
    public class SecurityTokenCreatingContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a <see cref="SecurityTokenValidatedContext"/>
        /// </summary>
        public SecurityTokenCreatingContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        public SecurityTokenCreatingOptions TokenOptions { get; internal set; }
        /// <summary>
        /// Gets the saml authn request identifier.
        /// </summary>
        /// <value>
        /// The saml authn request identifier.
        /// </value>
        public string SamlAuthnRequestId { get; internal set; }
    }
}
