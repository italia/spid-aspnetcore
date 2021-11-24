namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public class AssertionConsumerService
    {
        public ProtocolBinding ProtocolBinding { get; set; }
        public string Location { get; set; }
        public ushort Index { get; set; } = 0;
        public bool IsDefault { get; set; } = true;
    }
}
