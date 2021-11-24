using SPID.AspNetCore.Authentication.Saml.Aggregated;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public sealed class ServiceProviderPublicFullAggregator : ServiceProviderPublicAggregator
    {
        public override string CodiceAttivita => "pub-ag-full";

        public override ItemChoiceType1 TipoAttivita => ItemChoiceType1.PublicServicesFullAggregator;
    }
}
