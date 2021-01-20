using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication.Events
{
    public class SpidEvents : RemoteAuthenticationEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        public Func<RedirectContext, Task> OnRedirectToIdentityProvider { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a wsignoutcleanup request is received at the RemoteSignOutPath endpoint.
        /// </summary>
        public Func<RemoteSignOutContext, Task> OnRemoteSignOut { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked before creating saml token
        /// </summary>
        public Func<SecurityTokenCreatingContext, Task> OnTokenCreating { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        public virtual Task RedirectToIdentityProvider(RedirectContext context) => OnRedirectToIdentityProvider(context);

        /// <summary>
        /// Invoked when a wsignoutcleanup request is received at the RemoteSignOutPath endpoint.
        /// </summary>
        public virtual Task RemoteSignOut(RemoteSignOutContext context) => OnRemoteSignOut(context);

        /// <summary>
        /// Invoked before creating saml token
        /// </summary>
        public virtual Task TokenCreating(SecurityTokenCreatingContext context) => OnTokenCreating(context);
    }
}
