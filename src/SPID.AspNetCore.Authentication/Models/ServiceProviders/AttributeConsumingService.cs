namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public class AttributeConsumingService
    {
        public ushort Index { get; set; } = 0;
        public string ServiceName { get; set; }
        public string ServiceDescription { get; set; }
        public SpidClaimTypes[] ClaimTypes { get; set; }
    }
}
