using System.Collections.Generic;
using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public interface IServiceProvidersFactory
    {
        Task<List<ServiceProvider>> GetServiceProviders();
    }
}
