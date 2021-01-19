using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Models.IdP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using System.Xml.Serialization;

namespace SPID.AspNetCore.Authentication
{
    public class SpidHandler : RemoteAuthenticationHandler<SpidOptions>, IAuthenticationSignOutHandler
    {
        private const string CorrelationProperty = ".xsrf";

        /// <summary>
        /// Creates a new SpidAuthenticationHandler
        /// </summary>
        /// <param name="options"></param>
        /// <param name="encoder"></param>
        /// <param name="clock"></param>
        /// <param name="logger"></param>
        public SpidHandler(IOptionsMonitor<SpidOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new SpidEvents Events
        {
            get { return (SpidEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new SpidEvents());

        /// <summary>
        /// Overridden to handle remote signout requests
        /// </summary>
        /// <returns></returns>
        public override Task<bool> HandleRequestAsync()
        {
            // RemoteSignOutPath and CallbackPath may be the same, fall through if the message doesn't match.
            if (Options.RemoteSignOutPath.HasValue && Options.RemoteSignOutPath == Request.Path && HttpMethods.IsGet(Request.Method))
            {
                // We've received a remote sign-out request
                return HandleRemoteSignOutAsync();
            }

            return base.HandleRequestAsync();
        }

        /// <summary>
        /// Handles Challenge
        /// </summary>
        /// <returns></returns>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Save the original challenge URI so we can redirect back to it when we're done.
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
            }

            var idpName = Request.Query["idpName"];

            // Create the SPID request id
            string samlAuthnRequestId = Guid.NewGuid().ToString();
            // Select the Identity Provider
            var idp = Options.IdentityProviders.FirstOrDefault(x => x.Name == idpName);

            // Create the signed SAML request
            var (signedBase64, original, serializedOriginal) = SamlHelper.BuildAuthnPostRequest(
                uuid: samlAuthnRequestId,
                destination: idp.SingleSignOnServiceUrl,
                entityId: Options.EntityId,
                assertionConsumerServiceIndex: Options.AssertionConsumerServiceIndex,
                securityLevel: 2,
                certificate: Options.Certificate,
                identityProvider: idp);

            GenerateCorrelationId(properties);

            var redirectContext = new RedirectContext(Context, Scheme, Options, properties)
            {
                SignedProtocolMessage = signedBase64
            };
            await Events.RedirectToIdentityProvider(redirectContext);

            if (redirectContext.Handled)
            {
                return;
            }

            signedBase64 = redirectContext.SignedProtocolMessage;

            properties.Items.Add("IdpName", idpName);
            properties.Items.Add("Request", serializedOriginal);

            Response.Cookies.Append("SPID-Properties", Options.StateDataFormat.Protect(properties));

            string redirectUri = GetRedirectUrl(idp.SingleSignOnServiceUrl, samlAuthnRequestId, signedBase64, Options.Certificate);
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                Logger.MalformedRedirectUri(redirectUri);
            }
            Response.Redirect(redirectUri);
        }

        public string GetRedirectUrl(string signOnSignOutUrl, string samlAuthnRequestId, string data, X509Certificate2 certificate)
        {
            var samlEndpoint = signOnSignOutUrl;

            var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";

            var dict = new Dictionary<string, StringValues>()
            {
                { "SAMLRequest", data }
            };

            dict.Add("RelayState", samlAuthnRequestId);
            dict.Add("SigAlg", SamlConst.SignatureMethod);

            var queryStringNoSignature = BuildURLParametersString(parameters: new QueryCollection(dict)).Substring(1);

            var signatureQuery = queryStringNoSignature.CreateSignature(certificate);

            dict.Add("Signature", signatureQuery);

            return samlEndpoint + queryStringSeparator + BuildURLParametersString(parameters: new QueryCollection(dict)).Substring(1);
        }

        private string BuildURLParametersString(IQueryCollection parameters)
        {
            UriBuilder uriBuilder = new UriBuilder();
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            foreach (var urlParameter in parameters)
            {
                query[urlParameter.Key] = urlParameter.Value;
            }
            uriBuilder.Query = query.ToString();
            return uriBuilder.Query;
        }

        /// <summary>
        /// Invoked to process incoming authentication messages.
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            Response SpidMessage = null;
            AuthenticationProperties properties = null;

            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();

                SpidMessage = SamlHelper.GetAuthnResponse(form["SAMLResponse"].ToString());
            }

            if (SpidMessage == null)
            {
                if (Options.SkipUnrecognizedRequests)
                {
                    // Not for us?
                    return HandleRequestResult.SkipHandler();
                }

                return HandleRequestResult.Fail("No message.");
            }

            try
            {
                var id = SpidMessage.InResponseTo.Replace("_", "");

                Request.Cookies.TryGetValue("SPID-Properties", out var state);
                properties = Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                {
                    if (!Options.AllowUnsolicitedLogins)
                    {
                        return HandleRequestResult.Fail("Unsolicited logins are not allowed.");
                    }
                }
                // Extract the user state from properties and reset.
                properties.Items.TryGetValue("IdpName", out var idpName);
                properties.Items.TryGetValue("Request", out var serializedRequest);

                XmlSerializer requestSerializer = new XmlSerializer(typeof(AuthnRequestType));
                using var stringReader = new StringReader(serializedRequest);
                using XmlReader requestReader = XmlReader.Create(stringReader);
                var request = requestSerializer.Deserialize(requestReader) as AuthnRequestType;

                var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options, properties)
                {
                    ProtocolMessage = SpidMessage
                };
                await Events.MessageReceived(messageReceivedContext);
                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }
                SpidMessage = messageReceivedContext.ProtocolMessage;
                properties = messageReceivedContext.Properties; // Provides a new instance if not set.

                // If state did flow from the challenge then validate it. See AllowUnsolicitedLogins above.
                if (properties.Items.TryGetValue(CorrelationProperty, out string correlationId)
                    && !ValidateCorrelationId(properties))
                {
                    return HandleRequestResult.Fail("Correlation failed.", properties);
                }

                var (principal, validFrom, validTo) = ElaborateSamlResponse(SpidMessage, id, request, idpName);

                if (Options.UseTokenLifetime && validFrom != null && validTo != null)
                {
                    // Override any session persistence to match the token lifetime.
                    var issued = validFrom;
                    if (issued != DateTime.MinValue)
                    {
                        properties.IssuedUtc = issued.Value.ToUniversalTime();
                    }
                    var expires = validTo;
                    if (expires != DateTime.MinValue)
                    {
                        properties.ExpiresUtc = expires.Value.ToUniversalTime();
                    }
                    properties.AllowRefresh = false;
                }

                properties.Items.Add("SubjectNameId", SpidMessage.Assertion.Subject?.NameID?.Text);
                properties.Items.Add("SessionIndex", SpidMessage.Assertion.AuthnStatement.SessionIndex);

                return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
            }
            catch (Exception exception)
            {
                Logger.ExceptionProcessingMessage(exception);

                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    ProtocolMessage = SpidMessage,
                    Exception = exception
                };
                await Events.AuthenticationFailed(authenticationFailedContext);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                return HandleRequestResult.Fail(exception, properties);
            }
        }

        private (ClaimsPrincipal principal, DateTimeOffset? validFrom, DateTimeOffset? validTo) ElaborateSamlResponse(Response idpAuthnResponse, string id, AuthnRequestType request, string idPName)
        {
            var idp = Options.IdentityProviders.FirstOrDefault(x => x.Name == idPName);

            EntityDescriptor metadataIdp = !string.IsNullOrWhiteSpace(idp.OrganizationUrlMetadata)
                ? idp.OrganizationUrlMetadata.DownloadMetadataIDP()
                : new EntityDescriptor();
            idpAuthnResponse.ValidateAuthnResponse(request, metadataIdp, true);

            var claims = new Claim[]
            {
                new Claim( SamlConst.name, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.name.Equals(x.Name) || SamlConst.name.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.email, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.email.Equals(x.Name) || SamlConst.email.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.familyName, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.familyName.Equals(x.Name) || SamlConst.familyName.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.fiscalNumber, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.fiscalNumber.Equals(x.Name) || SamlConst.fiscalNumber.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.surname, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.surname.Equals(x.Name) || SamlConst.surname.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.mail, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.mail.Equals(x.Name) || SamlConst.mail.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.address, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.address.Equals(x.Name) || SamlConst.address.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.companyName, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.companyName.Equals(x.Name) || SamlConst.companyName.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.countyOfBirth, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.countyOfBirth.Equals(x.Name) || SamlConst.countyOfBirth.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.dateOfBirth, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.dateOfBirth.Equals(x.Name) || SamlConst.dateOfBirth.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.digitalAddress, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.digitalAddress.Equals(x.Name) || SamlConst.digitalAddress.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.expirationDate, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.expirationDate.Equals(x.Name) || SamlConst.expirationDate.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.gender, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.gender.Equals(x.Name) || SamlConst.gender.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.idCard, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.idCard.Equals(x.Name) || SamlConst.idCard.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.ivaCode, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.ivaCode.Equals(x.Name) || SamlConst.ivaCode.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.mobilePhone, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.mobilePhone.Equals(x.Name) || SamlConst.mobilePhone.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.placeOfBirth, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.placeOfBirth.Equals(x.Name) || SamlConst.placeOfBirth.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.registeredOffice, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.registeredOffice.Equals(x.Name) || SamlConst.registeredOffice.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( SamlConst.spidCode, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.spidCode.Equals(x.Name) || SamlConst.spidCode.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);

            var returnedPrincipal = new ClaimsPrincipal(identity);
            return (returnedPrincipal, DateTimeOffset.Parse(idpAuthnResponse.IssueInstant), DateTimeOffset.Parse(idpAuthnResponse.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter));
        }

        /// <summary>
        /// Handles Signout
        /// </summary>
        /// <returns></returns>
        public async virtual Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }

            string samlAuthnRequestId = Guid.NewGuid().ToString();
            Request.Cookies.TryGetValue("SPID-Properties", out var state);
            var requestProperties = Options.StateDataFormat.Unprotect(state);

            // Extract the user state from properties and reset.
            requestProperties.Items.TryGetValue("IdpName", out var idpName);
            requestProperties.Items.TryGetValue("SubjectNameId", out var subjectNameId);
            requestProperties.Items.TryGetValue("SessionIndex", out var sessionIndex);
            var idp = Options.IdentityProviders.FirstOrDefault(i => i.Name == idpName);

            var (signed, logoutRequest) = SamlHelper.BuildLogoutPostRequest(
                uuid: samlAuthnRequestId,
                consumerServiceURL: idp.SingleSignOnServiceUrl,
                subjectNameId: subjectNameId,
                authnStatementSessionIndex: sessionIndex,
                certificate: Options.Certificate,
                identityProvider: idp);

            var redirectContext = new RedirectContext(Context, Scheme, Options, properties)
            {
                SignedProtocolMessage = signed
            };
            await Events.RedirectToIdentityProvider(redirectContext);

            if (!redirectContext.Handled)
            {
                var redirectUri = GetRedirectUrl(idp.SingleSignOutServiceUrl, samlAuthnRequestId, signed, Options.Certificate);
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    Logger.MalformedRedirectUri(redirectUri);
                }
                Response.Redirect(redirectUri);
            }
        }

        /// <summary>
        /// Handles wsignoutcleanup1.0 messages sent to the RemoteSignOutPath
        /// </summary>
        /// <returns></returns>
        protected virtual async Task<bool> HandleRemoteSignOutAsync()
        {
            IdpLogoutResponse SpidMessage = null;

            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();

                SpidMessage = SamlHelper.GetLogoutResponse(form["SAMLResponse"].ToString());
            }

            if (!SpidMessage.IsSuccessful || !SamlHelper.ValidLogoutResponse(SpidMessage, SpidMessage.Id))
            {
                Logger.RemoteSignOutFailed();
                return false;
            }

            var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options, SpidMessage);
            await Events.RemoteSignOut(remoteSignOutContext);

            if (remoteSignOutContext.Result != null)
            {
                if (remoteSignOutContext.Result.Handled)
                {
                    Logger.RemoteSignOutHandledResponse();
                    return true;
                }
                if (remoteSignOutContext.Result.Skipped)
                {
                    Logger.RemoteSignOutSkipped();
                    return false;
                }
            }

            Logger.RemoteSignOut();

            await Context.SignOutAsync(Options.SignOutScheme);
            return true;
        }

        /// <summary>
        /// Build a redirect path if the given path is a relative path.
        /// </summary>
        private string BuildRedirectUriIfRelative(string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                return uri;
            }

            if (!uri.StartsWith("/", StringComparison.Ordinal))
            {
                return uri;
            }

            return BuildRedirectUri(uri);
        }
    }
}
