using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;
using System;

namespace SPID.AspNetCore.Authentication.Events
{
    public class AuthenticationFailedContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a new context object
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        public AuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options)
            : base(context, scheme, options, new AuthenticationProperties())
        { }

        /// <summary>
        /// The <see cref="Response"/> from the request, if any.
        /// </summary>
        public Response ProtocolMessage { get; set; }

        /// <summary>
        /// The <see cref="Exception"/> that triggered this event.
        /// </summary>
        public Exception Exception { get; set; }
    }
}
