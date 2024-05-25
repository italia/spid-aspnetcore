using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public abstract class ServiceProvider
    {
        public string FileName { get; set; }
        public Guid Id { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public string Language { get; set; } = "it";
        public List<SingleLogoutService> SingleLogoutServiceLocations { get; set; } = new();
        public List<AssertionConsumerService> AssertionConsumerServices { get; set; } = new();
        public List<AttributeConsumingService> AttributeConsumingServices { get; set; } = new();

        public abstract (string result, string contentType) Serialize();
    }
}
