using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Saml;
using System;

namespace SPID.AspNetCore.Authentication.Events
{
    public sealed class AuthenticationFailedContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a new context object
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        public AuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, ResponseType message, Exception exception)
            : base(context, scheme, options, new AuthenticationProperties())
        {
            ProtocolMessage = message;
            Exception = exception;
        }

        /// <summary>
        /// The <see cref="Response"/> from the request, if any.
        /// </summary>
        public ResponseType ProtocolMessage { get; set; }

        /// <summary>
        /// The <see cref="Exception"/> that triggered this event.
        /// </summary>
        public Exception Exception { get; set; }
    }
}
