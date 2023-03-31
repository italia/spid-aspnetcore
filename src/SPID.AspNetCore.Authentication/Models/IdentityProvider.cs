using System.Collections.Generic;

namespace SPID.AspNetCore.Authentication.Models
{
    public sealed class IdentityProvider
    {
        public string EntityId { get; set; }
        public string Name { get; set; }
        public string OrganizationName { get; set; }
        public string OrganizationDisplayName { get; set; }
        public List<string> X509SigningCertificates { get; set; }
        public string OrganizationLogoUrl { get; set; }
        public string SingleSignOnServiceUrlPost { get; set; }
        public string SingleSignOutServiceUrlPost { get; set; }
        public string SingleSignOnServiceUrlRedirect { get; set; }
        public string SingleSignOutServiceUrlRedirect { get; set; }
        public string DateTimeFormat { get; internal set; }
        public double? NowDelta { get; internal set; }
        public string SubjectNameIdRemoveText { get; set; } = "SPID-";
        public ProviderType ProviderType { get; set; } = ProviderType.IdentityProvider;
        public ushort AttributeConsumingServiceIndex { get; set; }

        public string GetSingleSignOnServiceUrl(RequestMethod requestMethod)
            => requestMethod == RequestMethod.Post
                ? SingleSignOnServiceUrlPost
                : SingleSignOnServiceUrlRedirect;

        public string GetSingleSignOutServiceUrl(RequestMethod requestMethod)
            => requestMethod == RequestMethod.Post
                ? SingleSignOutServiceUrlPost
                : SingleSignOutServiceUrlRedirect;
    }
}
