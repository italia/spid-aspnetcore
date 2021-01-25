using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Saml;

namespace SPID.AspNetCore.Authentication.Events
{
    public class MessageReceivedContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="properties"></param>
        public MessageReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            SpidOptions options,
            AuthenticationProperties properties,
            ResponseType protocolMessage)
            : base(context, scheme, options, properties)
        {
            ProtocolMessage = protocolMessage;
        }

        /// <summary>
        /// The <see cref="Response"/> received on this request.
        /// </summary>
        public ResponseType ProtocolMessage { get; set; }
    }
}
