namespace SPID.AspNetCore.Authentication.Models
{
    public class IdentityProvider
    {
        public string Name { get; set; }
        public string OrganizationName { get; set; }
        public string OrganizationDisplayName { get; set; }
        public string OrganizationUrlMetadata { get; set; }
        public string OrganizationUrl { get; set; }
        public string OrganizationLogoUrl { get; set; }
        public string SingleSignOnServiceUrl { get; set; }
        public string SingleSignOutServiceUrl { get; set; }
        public RequestMethod Method { get; set; } = RequestMethod.Post;
        public string DateTimeFormat { get; internal set; }
        public double? NowDelta { get; internal set; }
        public string SubjectNameIdRemoveText { get; set; } = "SPID-";
        public ProviderType ProviderType { get; set; } = ProviderType.IdentityProvider;
        public int SecurityLevel { get; set; }
    }
}
