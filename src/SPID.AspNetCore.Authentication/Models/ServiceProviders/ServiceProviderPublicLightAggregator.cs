using SPID.AspNetCore.Authentication.Saml.Aggregated;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public sealed class ServiceProviderPublicLightAggregator : ServiceProviderPublicAggregator
    {
        public override string CodiceAttivita => "pub-ag-lite";

        public override ItemChoiceType1 TipoAttivita => ItemChoiceType1.PublicServicesLightAggregator;
    }
}
