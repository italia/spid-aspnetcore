using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace SPID.AspNetCore.Authentication.Events
{
    public class RedirectContext : PropertiesContext<SpidOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="properties"></param>
        public RedirectContext(
            HttpContext context,
            AuthenticationScheme scheme,
            SpidOptions options,
            AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        /// <summary>
        /// The <see cref="LogoutRequestType"/> used to compose the redirect.
        /// </summary>
        public string SignedProtocolMessage { get; set; }

        /// <summary>
        /// If true, will skip any default logic for this redirect.
        /// </summary>
        public bool Handled { get; private set; }

        /// <summary>
        /// Skips any default logic for this redirect.
        /// </summary>
        public void HandleResponse() => Handled = true;
    }
}
