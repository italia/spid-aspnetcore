using Microsoft.AspNetCore.Authentication;
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
        public static AuthenticationBuilder AddSpid(this AuthenticationBuilder builder)
            => builder.AddSpid(SpidDefaults.AuthenticationScheme, _ => { });

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
            return builder.AddRemoteScheme<SpidOptions, SpidHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
