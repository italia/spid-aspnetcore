using SPID.AspNetCore.Authentication.Saml.Aggregated;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public sealed class ServiceProviderPrivateLightAggregator : ServiceProviderPrivateAggregator
    {
        public override string CodiceAttivita => "pri-ag-lite";

        public override ItemChoiceType1 TipoAttivita => ItemChoiceType1.PrivateServicesLightAggregator;
    }
}
