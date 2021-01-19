using System.Collections.Generic;

namespace SPID.AspNetCore.Authentication.Models
{
    public class SamlIdentityProviderSettings
    {
        /// <summary>
        /// The single sign on service URL
        /// </summary>
        public const string SingleSignOnServiceUrl = "SingleSignOnServiceUrl";

        /// <summary>
        /// The single logout service URL
        /// </summary>
        public const string SingleLogoutServiceUrl = "SingleLogoutServiceUrl";

        /// <summary>
        /// The subject name identifier remove text
        /// </summary>
        public const string SubjectNameIdRemoveText = "SubjectNameIdRemoveText";

        /// <summary>
        /// The date time format
        /// </summary>
        public const string DateTimeFormat = "DateTimeFormat";

        /// <summary>
        /// The now delta
        /// </summary>
        public const string NowDelta = "NowDelta";

        /// <summary>
        /// The EntityId
        /// </summary>
        public const string EntityId = "EntityId";

        /// <summary>
        /// The AssertionConsumerServiceIndex
        /// </summary>
        public const string AssertionConsumerServiceIndex = "AssertionConsumerServiceIndex";

        public const string Method = "Method";

        /// <summary>
        /// Gets the default settings.
        /// </summary>
        /// <value>
        /// The default settings.
        /// </value>
        public static Dictionary<string, string> DefaultSettings
        {
            get
            {
                return new Dictionary<string, string>(){
                    { SingleSignOnServiceUrl,string.Empty },
                    { SingleLogoutServiceUrl,string.Empty },
                    { SubjectNameIdRemoveText,string.Empty },
                    { DateTimeFormat,"yyyy-MM-ddTHH:mm:ss.fffZ" },
                    { NowDelta,"0" },
                    { EntityId,string.Empty },
                    { AssertionConsumerServiceIndex, "0"},
                    { Method, "Post"}
                };
            }
        }

    }
}
