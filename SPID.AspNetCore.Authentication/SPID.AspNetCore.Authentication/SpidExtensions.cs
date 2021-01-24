using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

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
            => builder.AddSpid(SpidDefaults.AuthenticationScheme, configuration, _ => { });

        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the default authentication scheme, display name, and the given options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="SpidOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, IConfiguration configuration, Action<SpidOptions> configureOptions)
            => builder.AddSpid(SpidDefaults.AuthenticationScheme, configuration, configureOptions);

        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the given authentication scheme, default display name, and the given options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="SpidOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, string authenticationScheme, IConfiguration configuration, Action<SpidOptions> configureOptions)
            => builder.AddSpid(authenticationScheme, SpidDefaults.DisplayName, configuration, configureOptions);

        /// <summary>
        /// Registers the <see cref="SpidHandler"/> using the given authentication scheme, display name, and options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="displayName"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="SpidOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder, string authenticationScheme, string displayName, IConfiguration configuration, Action<SpidOptions> configureOptions)
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
            builder.Services.AddOptions<SpidConfiguration>().Configure(o => OptionsHelper.LoadFromConfiguration(o, configuration));
            return builder.AddRemoteScheme<SpidOptions, SpidHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
