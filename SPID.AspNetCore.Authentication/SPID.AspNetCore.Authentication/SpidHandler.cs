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
using System.IO.Compression;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
        EventsHandler _eventsHandler;
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
            _eventsHandler = new EventsHandler(Events);
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

        public override async Task<bool> ShouldHandleRequestAsync()
        {
            var result = await base.ShouldHandleRequestAsync();
            if (!result)
            {
                result = Options.RemoteSignOutPath == Request.Path;
            }
            return result;
        }

        /// <summary>
        /// Overridden to handle remote signout requests
        /// </summary>
        /// <returns></returns>
        public override Task<bool> HandleRequestAsync()
        {
            // RemoteSignOutPath and CallbackPath may be the same, fall through if the message doesn't match.
            if (Options.RemoteSignOutPath.HasValue && Options.RemoteSignOutPath == Request.Path)
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


            var securityTokenCreatingContext = await _eventsHandler.HandleSecurityTokenCreatingContext(Context, Scheme, Options, properties, samlAuthnRequestId);

            // Create the signed SAML request
            var (base64SignedMessage, message) = SamlHelper.BuildAuthnPostRequest(
                samlAuthnRequestId,
                securityTokenCreatingContext.TokenOptions.EntityId,
                securityTokenCreatingContext.TokenOptions.AssertionConsumerServiceIndex,
                securityTokenCreatingContext.TokenOptions.AttributeConsumingServiceIndex,
                2,
                securityTokenCreatingContext.TokenOptions.Certificate,
                idp);

            GenerateCorrelationId(properties);

            var (redirectHandled, afterRedirectBase64SignedMessage) = await _eventsHandler.HandleRedirectToIdentityProvider(Context, Scheme, Options, properties, base64SignedMessage);
            if (redirectHandled)
            {
                return;
            }
            base64SignedMessage = afterRedirectBase64SignedMessage;

            properties.SetIdentityProviderName(idpName);
            properties.SetAuthenticationRequest(message);
            properties.Save(Response, Options.StateDataFormat);

            if (idp.Method == RequestMethod.Post)
            {
                await Response.WriteAsync($"<html><head><title>Login</title></head><body><form id=\"spidform\" action=\"{idp.SingleSignOnServiceUrl}\" method=\"post\">" +
                      $"<input type=\"hidden\" name=\"SAMLRequest\" value=\"{base64SignedMessage}\" />" +
                      $"<input type=\"hidden\" name=\"RelayState\" value=\"{samlAuthnRequestId}\" />" +
                      $"<button id=\"btnLogin\">Login</button>" +
                      "<script>document.getElementById('btnLogin').click()</script>" +
                      "</form></body></html>");
            }
            else
            {
                string redirectUri = GetRedirectUrl(idp.SingleSignOnServiceUrl, samlAuthnRequestId, SamlHelper.SerializeMessage(message), Options.Certificate);
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    Logger.MalformedRedirectUri(redirectUri);
                }
                Response.Redirect(redirectUri);
            }
        }

        public static string ZipStr(String str)
        {
            using MemoryStream output = new MemoryStream();
            using (DeflateStream gzip = new DeflateStream(output, CompressionMode.Compress))
            {
                using StreamWriter writer = new StreamWriter(gzip, System.Text.Encoding.UTF8);
                writer.Write(str);
            }

            return Convert.ToBase64String(output.ToArray());
        }

        public string GetRedirectUrl(string signOnSignOutUrl, string samlAuthnRequestId, string data, X509Certificate2 certificate)
        {
            var samlEndpoint = signOnSignOutUrl;

            var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";

            var dict = new Dictionary<string, StringValues>()
            {
                { "SAMLRequest", ZipStr(data) },
                { "RelayState", samlAuthnRequestId },
                { "SigAlg", SamlConst.SignatureMethod}
            };

            var queryStringNoSignature = BuildURLParametersString(dict).Substring(1);

            var signatureQuery = queryStringNoSignature.CreateSignature(certificate);

            dict.Add("Signature", signatureQuery);

            return samlEndpoint + queryStringSeparator + BuildURLParametersString(dict).Substring(1);
        }

        private string BuildURLParametersString(Dictionary<string, StringValues> parameters)
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

        private static readonly XmlSerializer logoutRequestSerializer = new XmlSerializer(typeof(LogoutRequestType));

        /// <summary>
        /// Invoked to process incoming authentication messages.
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            Response SpidMessage = null;
            AuthenticationProperties properties = new AuthenticationProperties();
            properties.Load(Request, Options.StateDataFormat);

            string id = null;
            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();

                SpidMessage = SamlHelper.GetAuthnResponse(form["SAMLResponse"].ToString());
                id = form["RelayState"].ToString();
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

                if (properties == null)
                {
                    if (!Options.AllowUnsolicitedLogins)
                    {
                        return HandleRequestResult.Fail("Unsolicited logins are not allowed.");
                    }
                }
                // Extract the user state from properties and reset.
                var idpName = properties.GetIdentityProviderName();
                var request = properties.GetAuthenticationRequest();

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
                if (properties.GetCorrelationProperty() != null && !ValidateCorrelationId(properties))
                {
                    return HandleRequestResult.Fail("Correlation failed.", properties);
                }

                var (principal, validFrom, validTo) = ElaborateSamlResponse(SpidMessage, request, idpName);

                if (Options.UseTokenLifetime && validFrom != null && validTo != null)
                {
                    // Override any session persistence to match the token lifetime.
                    var issued = validFrom;
                    if (issued != DateTimeOffset.MinValue)
                    {
                        properties.IssuedUtc = issued.Value.ToUniversalTime();
                    }
                    var expires = validTo;
                    if (expires != DateTimeOffset.MinValue)
                    {
                        properties.ExpiresUtc = expires.Value.ToUniversalTime();
                    }
                    properties.AllowRefresh = false;
                }

                properties.SetSubjectNameId(SpidMessage.Assertion.Subject?.NameID?.Text);
                properties.SetSessionIndex(SpidMessage.Assertion.AuthnStatement.SessionIndex);
                properties.Save(Response, Options.StateDataFormat);

                var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
                var authenticationSuccessContext = new AuthenticationSuccessContext(Context, Scheme, Options)
                {
                    SamlAuthnRequestId = id,
                    AuthenticationTicket = ticket
                };
                await Events.AuthenticationSuccess(authenticationSuccessContext);
                return HandleRequestResult.Success(ticket);
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

        private (ClaimsPrincipal principal, DateTimeOffset? validFrom, DateTimeOffset? validTo) ElaborateSamlResponse(Response idpAuthnResponse,
            AuthnRequestType request,
            string idPName)
        {
            var idp = Options.IdentityProviders.FirstOrDefault(x => x.Name == idPName);

            EntityDescriptor metadataIdp = !string.IsNullOrWhiteSpace(idp.OrganizationUrlMetadata)
                ? idp.OrganizationUrlMetadata.DownloadMetadataIDP()
                : new EntityDescriptor();
            idpAuthnResponse.ValidateAuthnResponse(request, metadataIdp, idp.PerformFullResponseValidation);

            var claims = new Claim[]
            {
                new Claim( ClaimTypes.NameIdentifier, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.email.Equals(x.Name) || SamlConst.email.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
                new Claim( ClaimTypes.Email, idpAuthnResponse.Assertion.AttributeStatement.Attribute.FirstOrDefault(x => SamlConst.email.Equals(x.Name) || SamlConst.email.Equals(x.FriendlyName))?.AttributeValue?.Trim() ?? string.Empty),
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
            var identity = new ClaimsIdentity(claims, Scheme.Name, SamlConst.email, null);

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

            var (signed, logoutRequest, serializedOriginal) = SamlHelper.BuildLogoutPostRequest(
                uuid: samlAuthnRequestId,
                consumerServiceURL: Options.EntityId,
                subjectNameId: subjectNameId,
                authnStatementSessionIndex: sessionIndex,
                certificate: Options.Certificate,
                identityProvider: idp);

            var redirectContext = new RedirectContext(Context, Scheme, Options, properties)
            {
                SignedProtocolMessage = signed
            };
            await Events.RedirectToIdentityProvider(redirectContext);

            properties.Items.Add("Request", serializedOriginal);
            Response.Cookies.Append("SPID-Properties", Options.StateDataFormat.Protect(properties));

            if (!redirectContext.Handled)
            {
                if (idp.Method == RequestMethod.Post)
                {
                    await Response.WriteAsync($"<html><head><title>Login</title></head><body><form id=\"spidform\" action=\"{idp.SingleSignOutServiceUrl}\" method=\"post\">" +
                          $"<input type=\"hidden\" name=\"SAMLRequest\" value=\"{signed}\" />" +
                          $"<input type=\"hidden\" name=\"RelayState\" value=\"{samlAuthnRequestId}\" />" +
                          $"<button id=\"btnLogout\">Logout</button>" +
                          "<script>document.getElementById('btnLogout').click()</script>" +
                          "</form></body></html>");
                }
                else
                {
                    var redirectUri = GetRedirectUrl(idp.SingleSignOutServiceUrl, samlAuthnRequestId, signed, Options.Certificate);
                    if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                    {
                        Logger.MalformedRedirectUri(redirectUri);
                    }
                    Response.Redirect(redirectUri);
                }
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

            Request.Cookies.TryGetValue("SPID-Properties", out var state);
            var requestProperties = Options.StateDataFormat.Unprotect(state);

            // Extract the user state from properties and reset.
            requestProperties.Items.TryGetValue("Request", out var serializedRequest);
            using var stringReader = new StringReader(serializedRequest);
            using XmlReader requestReader = XmlReader.Create(stringReader);
            var request = logoutRequestSerializer.Deserialize(requestReader) as LogoutRequestType;


            if (!SpidMessage.IsSuccessful || !SamlHelper.ValidateLogoutResponse(SpidMessage, request))
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
            Response.Redirect(requestProperties.RedirectUri);
            return true;
        }



        private class EventsHandler
        {
            private SpidEvents _events;
            public EventsHandler(SpidEvents events)
            {
                _events = events;
            }

            public async Task<SecurityTokenCreatingContext> HandleSecurityTokenCreatingContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties, string samlAuthnRequestId)
            {
                var securityTokenCreatingContext = new SecurityTokenCreatingContext(context, scheme, options, properties)
                {
                    SamlAuthnRequestId = samlAuthnRequestId,
                    TokenOptions = new SecurityTokenCreatingOptions
                    {
                        EntityId = options.EntityId,
                        Certificate = options.Certificate,
                        AssertionConsumerServiceIndex = options.AssertionConsumerServiceIndex,
                        AttributeConsumingServiceIndex = options.AttributeConsumingServiceIndex
                    }
                };
                await _events.TokenCreating(securityTokenCreatingContext);
                return securityTokenCreatingContext;
            }

            public async Task<(bool, string)> HandleRedirectToIdentityProvider(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties, string signedBase64)
            {
                var redirectContext = new RedirectContext(context, scheme, options, properties)
                {
                    SignedProtocolMessage = signedBase64
                };
                await _events.RedirectToIdentityProvider(redirectContext);

                return (redirectContext.Handled, redirectContext.SignedProtocolMessage);
            }
        }
    }

}

    internal static class AuthenticationPropertiesExtensions
    {
        public static void SetIdentityProviderName(this AuthenticationProperties properties, string name) => properties.Items["IdentityProviderName"] = name;
        public static string GetIdentityProviderName(this AuthenticationProperties properties) => properties.Items["IdentityProviderName"];

        public static void SetAuthenticationRequest(this AuthenticationProperties properties, AuthnRequestType request) => 
            properties.Items["AuthenticationRequest"] = SamlHelper.SerializeMessage(request);
        public static AuthnRequestType GetAuthenticationRequest(this AuthenticationProperties properties) => 
            SamlHelper.DeserializeMessage<AuthnRequestType>(properties.Items["AuthenticationRequest"]);

        public static void SetLogoutRequest(this AuthenticationProperties properties, LogoutRequestType request) =>
            properties.Items["LogoutRequest"] = SamlHelper.SerializeMessage(request);
        public static LogoutRequestType GetLogoutRequest(this AuthenticationProperties properties) =>
            SamlHelper.DeserializeMessage<LogoutRequestType>(properties.Items["LogoutRequest"]);

        public static void SetSubjectNameId(this AuthenticationProperties properties, string subjectNameId) => properties.Items["subjectNameId"] = subjectNameId;
        public static string GetSubjectNameId(this AuthenticationProperties properties) => properties.Items["subjectNameId"];

        public static void SetSessionIndex(this AuthenticationProperties properties, string sessionIndex) => properties.Items["SessionIndex"] = sessionIndex;
        public static string GetSessionIndex(this AuthenticationProperties properties) => properties.Items["SessionIndex"];

        public static void SetCorrelationProperty(this AuthenticationProperties properties, string correlationProperty) => properties.Items[".xsrf"] = correlationProperty;
        public static string GetCorrelationProperty(this AuthenticationProperties properties) => properties.Items[".xsrf"];

        public static void Save(this AuthenticationProperties properties, HttpResponse response, ISecureDataFormat<AuthenticationProperties> encryptor)
        {
            response.Cookies.Append("SPID-Properties", encryptor.Protect(properties));
        }

        public static void Load(this AuthenticationProperties properties, HttpRequest request, ISecureDataFormat<AuthenticationProperties> encryptor)
        {
            AuthenticationProperties cookieProperties = encryptor.Unprotect(request.Cookies["SPID-Properties"]);
            properties.AllowRefresh = cookieProperties.AllowRefresh;
            properties.ExpiresUtc = cookieProperties.ExpiresUtc;
            properties.IsPersistent = cookieProperties.IsPersistent;
            properties.IssuedUtc = cookieProperties.IssuedUtc;
            foreach(var item in cookieProperties.Items)
            {
                properties.Items.Add(item);
            }
            foreach (var item in cookieProperties.Parameters)
            {
                properties.Parameters.Add(item);
            }
            properties.RedirectUri = cookieProperties.RedirectUri;
        }
    }
}
