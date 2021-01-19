namespace SPID.AspNetCore.Authentication
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
        public string Method { get; set; }
        public string DateTimeFormat { get; internal set; }
        public string NowDelta { get; internal set; }
        public string SubjectNameIdRemoveText { get; set; } = "SPID-";
    }
}
