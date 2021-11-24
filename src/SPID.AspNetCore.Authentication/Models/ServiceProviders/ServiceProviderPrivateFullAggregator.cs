using SPID.AspNetCore.Authentication.Saml.Aggregated;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public sealed class ServiceProviderPrivateFullAggregator : ServiceProviderPrivateAggregator
    {
        public override string CodiceAttivita => "pri-ag-full";

        public override ItemChoiceType1 TipoAttivita => ItemChoiceType1.PrivateServicesFullAggregator;
    }
}
