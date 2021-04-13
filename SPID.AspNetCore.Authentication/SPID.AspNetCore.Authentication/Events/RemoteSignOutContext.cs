using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Saml;

namespace SPID.AspNetCore.Authentication.Events
{
    public sealed class RemoteSignOutContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="message"></param>
        public RemoteSignOutContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, LogoutResponseType message)
            : base(context, scheme, options, new AuthenticationProperties())
            => ProtocolMessage = message;

        /// <summary>
        /// The signout message.
        /// </summary>
        public LogoutResponseType ProtocolMessage { get; set; }
    }
}
