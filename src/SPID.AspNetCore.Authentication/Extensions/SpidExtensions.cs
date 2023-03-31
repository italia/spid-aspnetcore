using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Extensions;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Models.ServiceProviders;
using System;
using System.Security.Claims;

namespace SPID.AspNetCore.Authentication
{
    public static class SpidExtensions
    {
        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the default authentication scheme, display name, and options.
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, IConfiguration configuration)
            => builder.AddSpid(SpidDefaults.AuthenticationScheme, o => { o.LoadFromConfiguration(configuration); });

        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the default authentication scheme, display name, and the given options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="SpidOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, Action<SpidOptions> configureOptions)
            => builder.AddSpid(SpidDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the given authentication scheme, default display name, and the given options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="SpidOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, string authenticationScheme, Action<SpidOptions> configureOptions)
            => builder.AddSpid(authenticationScheme, SpidDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the given authentication scheme, display name, and options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="displayName"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="SpidOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<SpidOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SpidOptions>, SpidPostConfigureOptions>());
            builder.Services.TryAdd(ServiceDescriptor.Singleton<IActionContextAccessor, ActionContextAccessor>());
            builder.Services.AddHttpClient("spid");
            builder.Services.TryAddScoped(factory =>
            {
                var actionContext = factory.GetService<IActionContextAccessor>().ActionContext;
                var urlHelperFactory = factory.GetService<IUrlHelperFactory>();
                return urlHelperFactory.GetUrlHelper(actionContext);
            });
            builder.Services.AddOptions<SpidOptions>().Configure(configureOptions);
            builder.Services.TryAddScoped<IServiceProvidersFactory, DefaultServiceProvidersFactory>();
            builder.Services.TryAddScoped<ILogHandler, DefaultLogHandler>();
            return builder.AddRemoteScheme<SpidOptions, SpidHandler>(authenticationScheme, displayName, configureOptions);
        }

        public static AuthenticationBuilder AddServiceProvidersFactory<T>(this AuthenticationBuilder builder)
            where T : class, IServiceProvidersFactory
        {
            builder.Services.AddScoped<IServiceProvidersFactory, T>();
            return builder;
        }

        /// <summary>
        /// Adds the custom log handler.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddLogHandler<T>(this AuthenticationBuilder builder)
            where T : class, ILogHandler
        {
            builder.Services.AddScoped<ILogHandler, T>();
            return builder;
        }

        public static IApplicationBuilder AddSpidSPMetadataEndpoints(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SpidSPMetadataMiddleware>();
        }

        /// <summary>
        /// Finds the first value.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="claimType">Type of the claim.</param>
        /// <returns></returns>
        public static string FindFirstValue(this ClaimsPrincipal principal, SpidClaimTypes claimType)
        {
            return principal.FindFirstValue(claimType.Value);
        }

        /// <summary>
        /// Finds the first.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="claimType">Type of the claim.</param>
        /// <returns></returns>
        public static Claim FindFirst(this ClaimsPrincipal principal, SpidClaimTypes claimType)
        {
            return principal.FindFirst(claimType.Value);
        }
    }
}
