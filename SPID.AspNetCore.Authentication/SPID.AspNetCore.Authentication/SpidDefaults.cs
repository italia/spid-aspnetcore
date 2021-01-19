using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication
{
    /// <summary>
    /// Default values related to Spid authentication handler
    /// </summary>
    public static class SpidDefaults
    {
        /// <summary>
        /// The default authentication type used when registering the SpidHandler.
        /// </summary>
        public const string AuthenticationScheme = "Spid";

        /// <summary>
        /// The default display name used when registering the SpidHandler.
        /// </summary>
        public const string DisplayName = "Spid";

        /// <summary>
        /// Constant used to identify userstate inside AuthenticationProperties that have been serialized in the 'wctx' parameter.
        /// </summary>
        public static readonly string UserstatePropertiesKey = "Spid.Userstate";
    }
}
