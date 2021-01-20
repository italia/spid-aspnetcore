using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace SPID.AspNetCore.Authentication.Events
{
    public class SecurityTokenCreatingContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a <see cref="SecurityTokenValidatedContext"/>
        /// </summary>
        public SecurityTokenCreatingContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        public SecurityTokenCreatingOptions TokenOptions { get; set; }
    }
}
