using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;

namespace SPID.AspNetCore.Authentication.Events
{
    public class RemoteSignOutContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="message"></param>
        public RemoteSignOutContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, IdpLogoutResponse message)
            : base(context, scheme, options, new AuthenticationProperties())
            => ProtocolMessage = message;

        /// <summary>
        /// The signout message.
        /// </summary>
        public IdpLogoutResponse ProtocolMessage { get; set; }
    }
}
