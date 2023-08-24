using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Resources;
using SPID.AspNetCore.Authentication.Saml;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;

namespace SPID.AspNetCore.Authentication
{
    internal class SpidHandler : RemoteAuthenticationHandler<SpidOptions>, IAuthenticationSignOutHandler
    {
        EventsHandler _eventsHandler;
        RequestHandler _requestGenerator;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogHandler _logHandler;

        public SpidHandler(IOptionsMonitor<SpidOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IHttpClientFactory httpClientFactory,
            ILogHandler logHandler)
            : base(options, logger, encoder, clock)
        {
            _httpClientFactory = httpClientFactory;
            _logHandler = logHandler;
        }

        protected new SpidEvents Events
        {
            get { return (SpidEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new SpidEvents());

        /// <summary>
        /// Decides whether this handler should handle request based on request path. If it's true, HandleRequestAsync method is invoked.
        /// </summary>
        /// <returns>value indicating whether the request should be handled or not</returns>
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
        /// Handle the request and de
        /// </summary>
        /// <returns></returns>
        public override Task<bool> HandleRequestAsync()
        {
            _eventsHandler = new EventsHandler(Events);
            _requestGenerator = new RequestHandler(Response, Logger, _logHandler);

            // RemoteSignOutPath and CallbackPath may be the same, fall through if the message doesn't match.
            if (Options.RemoteSignOutPath.HasValue && Options.RemoteSignOutPath == Request.Path)
            {
                // We've received a remote sign-out request
                return HandleRemoteSignOutAsync();
            }

            return base.HandleRequestAsync();
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Save the original challenge URI so we can redirect back to it when we're done.
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
            }

            // Create the SPID request id
            string authenticationRequestId = Guid.NewGuid().ToString();

            // Select the Identity Provider
            var idpName = Request.Query["idpName"];
            var idp = (await Options.GetIdentityProviders(_httpClientFactory)).FirstOrDefault(x => x.Name == idpName);


            var securityTokenCreatingContext = await _eventsHandler.HandleSecurityTokenCreatingContext(Context,
                Scheme,
                Options,
                idp,
                properties,
                authenticationRequestId);

            // Create the signed SAML request
            var message = SamlHandler.GetAuthnRequest(
                authenticationRequestId,
                securityTokenCreatingContext.TokenOptions.EntityId,
                securityTokenCreatingContext.TokenOptions.AssertionConsumerServiceURL,
                securityTokenCreatingContext.TokenOptions.AssertionConsumerServiceIndex,
                securityTokenCreatingContext.TokenOptions.AttributeConsumingServiceIndex,
                securityTokenCreatingContext.TokenOptions.Certificate,
                securityTokenCreatingContext.TokenOptions.SecurityLevel,
                securityTokenCreatingContext.TokenOptions.RequestMethod,
                idp);

            GenerateCorrelationId(properties);

            var (redirectHandled, afterRedirectMessage) = await _eventsHandler.HandleRedirectToIdentityProviderForAuthentication(Context, Scheme, Options, properties, message);
            if (redirectHandled)
            {
                return;
            }
            message = afterRedirectMessage;

            properties.SetIdentityProviderName(idpName);
            properties.SetAuthenticationRequest(message);
            properties.Save(Response, Options.StateDataFormat);

            await _requestGenerator.HandleRequest(message,
                message.ID,
                securityTokenCreatingContext.TokenOptions.Certificate,
                idp.GetSingleSignOnServiceUrl(securityTokenCreatingContext.TokenOptions.RequestMethod),
                securityTokenCreatingContext.TokenOptions.RequestMethod);
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            AuthenticationProperties properties = new();
            ResponseType message = null;
            try
            {
                (string id, message, string serializedResponse) = await ExtractInfoFromAuthenticationResponse();

                properties.Load(Request, Options.StateDataFormat);

                var idpName = properties.GetIdentityProviderName();
                var request = properties.GetAuthenticationRequest();

                var responseMessageReceivedResult = await _eventsHandler.HandleAuthenticationResponseMessageReceived(Context, Scheme, Options, properties, message);
                if (responseMessageReceivedResult.Result != null)
                {
                    return responseMessageReceivedResult.Result;
                }
                message = responseMessageReceivedResult.ProtocolMessage;
                properties = responseMessageReceivedResult.Properties;

                var validationMessageResult = await ValidateAuthenticationResponse(message, request, properties, idpName, serializedResponse);
                if (validationMessageResult != null)
                    return validationMessageResult;

                var correlationValidationResult = ValidateCorrelation(properties);
                if (correlationValidationResult != null)
                {
                    return correlationValidationResult;
                }

                var (principal, validFrom, validTo) = CreatePrincipal(message);

                AdjustAuthenticationPropertiesDates(properties, validFrom, validTo);

                properties.SetSubjectNameId(message.GetAssertion().Subject?.GetNameID()?.Value);
                properties.SetSessionIndex(message.GetAssertion().GetAuthnStatement().SessionIndex);
                properties.Save(Response, Options.StateDataFormat);

                var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
                await _eventsHandler.HandleAuthenticationSuccess(Context, Scheme, Options, id, ticket);
                return HandleRequestResult.Success(ticket);
            }
            catch (Exception exception)
            {
                Logger.ExceptionProcessingMessage(exception);

                var authenticationFailedResult = await _eventsHandler.HandleAuthenticationFailed(Context, Scheme, Options, message, exception);
                return authenticationFailedResult.Result ?? HandleRequestResult.Fail(exception, properties);
            }
        }

        public async virtual Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }

            string authenticationRequestId = Guid.NewGuid().ToString();

            properties.Load(Request, Options.StateDataFormat);

            // Extract the user state from properties and reset.
            var idpName = properties.GetIdentityProviderName();
            var subjectNameId = properties.GetSubjectNameId();
            var sessionIndex = properties.GetSessionIndex();

            var idp = (await Options.GetIdentityProviders(_httpClientFactory)).FirstOrDefault(i => i.Name == idpName);

            var securityTokenCreatingContext = await _eventsHandler.HandleSecurityTokenCreatingContext(Context,
                Scheme,
                Options,
                idp,
                properties,
                authenticationRequestId);

            var message = SamlHandler.GetLogoutRequest(
                authenticationRequestId,
                securityTokenCreatingContext.TokenOptions.EntityId,
                securityTokenCreatingContext.TokenOptions.Certificate,
                idp,
                subjectNameId,
                sessionIndex,
                securityTokenCreatingContext.TokenOptions.RequestMethod);

            var (redirectHandled, afterRedirectMessage) = await _eventsHandler.HandleRedirectToIdentityProviderForSignOut(Context, Scheme, Options, properties, message);
            if (redirectHandled)
            {
                return;
            }
            message = afterRedirectMessage;

            properties.SetLogoutRequest(message);
            properties.Save(Response, Options.StateDataFormat);

            await _requestGenerator.HandleRequest(message,
                message.ID,
                securityTokenCreatingContext.TokenOptions.Certificate,
                idp.GetSingleSignOutServiceUrl(securityTokenCreatingContext.TokenOptions.RequestMethod),
                securityTokenCreatingContext.TokenOptions.RequestMethod);
        }

        protected virtual async Task<bool> HandleRemoteSignOutAsync()
        {
            var (message, serializedResponse) = await ExtractInfoFromSignOutResponse();

            AuthenticationProperties requestProperties = new AuthenticationProperties();
            requestProperties.Load(Request, Options.StateDataFormat);

            var logoutRequest = requestProperties.GetLogoutRequest();

            var validSignOut = ValidateSignOutResponse(message, logoutRequest, serializedResponse);
            if (!validSignOut)
                return false;

            var remoteSignOutContext = await _eventsHandler.HandleRemoteSignOut(Context, Scheme, Options, message);
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

        private async Task<HandleRequestResult> ValidateAuthenticationResponse(ResponseType response, AuthnRequestType request, AuthenticationProperties properties, string idpName, string serializedResponse)
        {
            if (response == null)
            {
                if (Options.SkipUnrecognizedRequests)
                {
                    return HandleRequestResult.SkipHandler();
                }

                return HandleRequestResult.Fail("No message.");
            }

            if (properties == null && !Options.AllowUnsolicitedLogins)
            {
                return HandleRequestResult.Fail("Unsolicited logins are not allowed.");
            }

            var idp = (await Options.GetIdentityProviders(_httpClientFactory)).FirstOrDefault(x => x.Name == idpName);

            response.ValidateAuthnResponse(request, idp, serializedResponse);
            return null;
        }

        private HandleRequestResult ValidateCorrelation(AuthenticationProperties properties)
        {
            if (properties.GetCorrelationProperty() != null && !ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }
            return null;
        }

        private void AdjustAuthenticationPropertiesDates(AuthenticationProperties properties, DateTimeOffset? validFrom, DateTimeOffset? validTo)
        {
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
        }

        private string GetAttributeValue(ResponseType response, string attributeName)
            => response.GetAssertion()?
                .GetAttributeStatement()?
                .GetAttributes()?
                .FirstOrDefault(x => attributeName.Equals(x.Name) || attributeName.Equals(x.FriendlyName))?
                .GetAttributeValue()?
                .Trim() ?? string.Empty;

        private string RemoveFiscalNumberPrefix(string fiscalNumber)
            => fiscalNumber?
                .Split(new char[] { '-' }, StringSplitOptions.RemoveEmptyEntries)
                .LastOrDefault() ?? string.Empty;

        private (ClaimsPrincipal principal, DateTimeOffset? validFrom, DateTimeOffset? validTo) CreatePrincipal(ResponseType idpAuthnResponse)
        {
            var claims = new List<Claim>
            {
                new Claim( SpidClaimTypes.Name.Value, GetAttributeValue(idpAuthnResponse, SamlConst.name)),
                new Claim( SpidClaimTypes.Email.Value, GetAttributeValue(idpAuthnResponse, SamlConst.email)),
                new Claim( SpidClaimTypes.FamilyName.Value, GetAttributeValue(idpAuthnResponse, SamlConst.familyName)),
                new Claim( SpidClaimTypes.FiscalNumber.Value, RemoveFiscalNumberPrefix(GetAttributeValue(idpAuthnResponse, SamlConst.fiscalNumber))),
                new Claim( SpidClaimTypes.RawFiscalNumber.Value, GetAttributeValue(idpAuthnResponse, SamlConst.fiscalNumber)),
                new Claim( SpidClaimTypes.Mail.Value, GetAttributeValue(idpAuthnResponse, SamlConst.mail)),
                new Claim( SpidClaimTypes.Address.Value, GetAttributeValue(idpAuthnResponse, SamlConst.address)),
                new Claim( SpidClaimTypes.CompanyName.Value, GetAttributeValue(idpAuthnResponse, SamlConst.companyName)),
                new Claim( SpidClaimTypes.CountyOfBirth.Value, GetAttributeValue(idpAuthnResponse, SamlConst.countyOfBirth)),
                new Claim( SpidClaimTypes.DateOfBirth.Value, GetAttributeValue(idpAuthnResponse, SamlConst.dateOfBirth)),
                new Claim( SpidClaimTypes.DigitalAddress.Value, GetAttributeValue(idpAuthnResponse, SamlConst.digitalAddress)),
                new Claim( SpidClaimTypes.ExpirationDate.Value, GetAttributeValue(idpAuthnResponse, SamlConst.expirationDate)),
                new Claim( SpidClaimTypes.Gender.Value, GetAttributeValue(idpAuthnResponse, SamlConst.gender)),
                new Claim( SpidClaimTypes.IdCard.Value, GetAttributeValue(idpAuthnResponse, SamlConst.idCard)),
                new Claim( SpidClaimTypes.IvaCode.Value, GetAttributeValue(idpAuthnResponse, SamlConst.ivaCode)),
                new Claim( SpidClaimTypes.MobilePhone.Value, GetAttributeValue(idpAuthnResponse, SamlConst.mobilePhone)),
                new Claim( SpidClaimTypes.PlaceOfBirth.Value, GetAttributeValue(idpAuthnResponse, SamlConst.placeOfBirth)),
                new Claim( SpidClaimTypes.RegisteredOffice.Value, GetAttributeValue(idpAuthnResponse, SamlConst.registeredOffice)),
                new Claim( SpidClaimTypes.SpidCode.Value, GetAttributeValue(idpAuthnResponse, SamlConst.spidCode)),
                new Claim( SpidClaimTypes.CompanyFiscalNumber.Value, GetAttributeValue(idpAuthnResponse, SamlConst.companyFiscalNumber)),
                new Claim( SpidClaimTypes.DomicileStreetAddress.Value, GetAttributeValue(idpAuthnResponse, SamlConst.domicileStreetAddress)),
                new Claim( SpidClaimTypes.DomicilePostalCode.Value, GetAttributeValue(idpAuthnResponse, SamlConst.domicilePostalCode)),
                new Claim( SpidClaimTypes.DomicileMunicipality.Value, GetAttributeValue(idpAuthnResponse, SamlConst.domicileMunicipality)),
                new Claim( SpidClaimTypes.DomicileProvince.Value, GetAttributeValue(idpAuthnResponse, SamlConst.domicileProvince)),
                new Claim( SpidClaimTypes.DomicileNation.Value, GetAttributeValue(idpAuthnResponse, SamlConst.domicileNation)),
            };

            claims.Add(new Claim(ClaimTypes.NameIdentifier, claims.FirstOrDefault(c => c.Type.Equals(Options.PrincipalNameClaimType.Value))?.Value));
            claims.Add(new Claim(ClaimTypes.Email, claims.FirstOrDefault(c => c.Type.Equals(SpidClaimTypes.Email.Value))?.Value));

            var identity = new ClaimsIdentity(claims, Scheme.Name, Options.PrincipalNameClaimType.Value, null);

            var returnedPrincipal = new ClaimsPrincipal(identity);
            return (returnedPrincipal, new DateTimeOffset(idpAuthnResponse.IssueInstant), new DateTimeOffset(idpAuthnResponse.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter));
        }

        private async Task<(string Id, ResponseType Message, string serializedResponse)> ExtractInfoFromAuthenticationResponse()
        {
            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();

                var serializedResponse = Encoding.UTF8.GetString(Convert.FromBase64String(form["SAMLResponse"].FirstOrDefault()));

                await _logHandler.LogPostResponse(new PostResponse()
                {
                    SignedMessage = serializedResponse,
                    SAMLResponse = form["SAMLResponse"].FirstOrDefault(),
                    RelayState = form["RelayState"].ToString(),
                    ContentType = Request.ContentType,
                    Url = Request.GetEncodedUrl(),
                    Headers = Request.Headers.ToDictionary(t => t.Key, t => t.Value),
                    Cookies = Request.Cookies.ToDictionary(t => t.Key, t => t.Value)
                });

                return (
                    form["RelayState"].ToString(),
                    SamlHandler.GetAuthnResponse(serializedResponse),
                    serializedResponse
                );
            }
            else if (HttpMethods.IsGet(Request.Method)
                && Request.Query.ContainsKey("SAMLResponse")
                && Request.Query.ContainsKey("RelayState"))
            {
                var serializedResponse = DecompressString(Request.Query["SAMLResponse"].FirstOrDefault());

                await _logHandler.LogRedirectResponse(new RedirectResponse()
                {
                    SignedMessage = serializedResponse,
                    SAMLResponse = Request.Query["SAMLResponse"].FirstOrDefault(),
                    RelayState = Request.Query["RelayState"].FirstOrDefault(),
                    Url = Request.GetEncodedUrl(),
                    Headers = Request.Headers.ToDictionary(t => t.Key, t => t.Value),
                    Cookies = Request.Cookies.ToDictionary(t => t.Key, t => t.Value)
                });

                return (
                    Request.Query["RelayState"].FirstOrDefault(),
                    SamlHandler.GetAuthnResponse(serializedResponse),
                    serializedResponse
                );
            }
            return (null, null, null);
        }

        private async Task<(LogoutResponseType Message, string serializedResponse)> ExtractInfoFromSignOutResponse()
        {
            if (HttpMethods.IsPost(Request.Method)
              && !string.IsNullOrEmpty(Request.ContentType)
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();

                var serializedResponse = Encoding.UTF8.GetString(Convert.FromBase64String(form["SAMLResponse"][0]));

                await _logHandler.LogPostResponse(new PostResponse()
                {
                    SignedMessage = serializedResponse,
                    SAMLResponse = form["SAMLResponse"].FirstOrDefault(),
                    RelayState = form["RelayState"].ToString(),
                    ContentType = Request.ContentType,
                    Url = Request.GetEncodedUrl(),
                    Headers = Request.Headers.ToDictionary(t => t.Key, t => t.Value),
                    Cookies = Request.Cookies.ToDictionary(t => t.Key, t => t.Value)
                });

                return (SamlHandler.GetLogoutResponse(serializedResponse),
                    serializedResponse
                );
            }
            else if (HttpMethods.IsGet(Request.Method)
                && Request.Query.ContainsKey("SAMLResponse")
                && Request.Query.ContainsKey("RelayState"))
            {
                var serializedResponse = DecompressString(Request.Query["SAMLResponse"].FirstOrDefault());

                await _logHandler.LogRedirectResponse(new RedirectResponse()
                {
                    SignedMessage = serializedResponse,
                    SAMLResponse = Request.Query["SAMLResponse"].FirstOrDefault(),
                    RelayState = Request.Query["RelayState"].FirstOrDefault(),
                    Url = Request.GetEncodedUrl(),
                    Headers = Request.Headers.ToDictionary(t => t.Key, t => t.Value),
                    Cookies = Request.Cookies.ToDictionary(t => t.Key, t => t.Value)
                });

                return (SamlHandler.GetLogoutResponse(serializedResponse),
                    serializedResponse
                );
            }
            return (null, null);
        }

        private static string DecompressString(string value)
        {
            using MemoryStream output = new MemoryStream(Convert.FromBase64String(value));
            using DeflateStream stream = new DeflateStream(output, CompressionMode.Decompress);
            using StreamReader reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd();
        }

        private bool ValidateSignOutResponse(LogoutResponseType response, LogoutRequestType request, string serializedResponse)
        {
            var valid = response.Status.StatusCode.Value == SamlConst.Success && SamlHandler.ValidateLogoutResponse(response, request, serializedResponse);
            if (valid)
            {
                return true;
            }

            Logger.RemoteSignOutFailed();
            return false;
        }

        private class EventsHandler
        {
            private readonly SpidEvents _events;

            public EventsHandler(SpidEvents events)
            {
                _events = events;
            }

            public async Task<SecurityTokenCreatingContext> HandleSecurityTokenCreatingContext(HttpContext context,
                AuthenticationScheme scheme,
                SpidOptions options,
                IdentityProvider idp,
                AuthenticationProperties properties,
                string samlAuthnRequestId)
            {
                var securityTokenCreatingContext = new SecurityTokenCreatingContext(context, scheme, options, properties)
                {
                    SamlAuthnRequestId = samlAuthnRequestId,
                    TokenOptions = new SecurityTokenCreatingOptions
                    {
                        EntityId = options.EntityId,
                        Certificate = options.Certificate,
                        AssertionConsumerServiceURL = options.AssertionConsumerServiceURL,
                        AssertionConsumerServiceIndex = options.AssertionConsumerServiceIndex,
                        AttributeConsumingServiceIndex = options.AttributeConsumingServiceIndex,
                        SecurityLevel = options.SecurityLevel,
                        RequestMethod = options.RequestMethod
                    }
                };
                await _events.TokenCreating(securityTokenCreatingContext);
                return securityTokenCreatingContext;
            }

            public async Task<(bool, AuthnRequestType)> HandleRedirectToIdentityProviderForAuthentication(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties, AuthnRequestType message)
            {
                var redirectContext = new RedirectContext(context, scheme, options, properties, message);
                await _events.RedirectToIdentityProvider(redirectContext);
                return (redirectContext.Handled, (AuthnRequestType)redirectContext.SignedProtocolMessage);
            }

            public async Task<(bool, LogoutRequestType)> HandleRedirectToIdentityProviderForSignOut(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties, LogoutRequestType message)
            {
                var redirectContext = new RedirectContext(context, scheme, options, properties, message);
                await _events.RedirectToIdentityProvider(redirectContext);
                return (redirectContext.Handled, (LogoutRequestType)redirectContext.SignedProtocolMessage);
            }

            public async Task<MessageReceivedContext> HandleAuthenticationResponseMessageReceived(HttpContext context, AuthenticationScheme scheme, SpidOptions options, AuthenticationProperties properties, ResponseType message)
            {
                var messageReceivedContext = new MessageReceivedContext(context, scheme, options, properties, message);
                await _events.MessageReceived(messageReceivedContext);
                return messageReceivedContext;
            }

            public async Task<AuthenticationSuccessContext> HandleAuthenticationSuccess(HttpContext context, AuthenticationScheme scheme, SpidOptions options, string authenticationRequestId, AuthenticationTicket ticket)
            {
                var authenticationSuccessContext = new AuthenticationSuccessContext(context, scheme, options, authenticationRequestId, ticket);
                await _events.AuthenticationSuccess(authenticationSuccessContext);
                return authenticationSuccessContext;
            }

            public async Task<AuthenticationFailedContext> HandleAuthenticationFailed(HttpContext context, AuthenticationScheme scheme, SpidOptions options, ResponseType message, Exception exception)
            {
                var authenticationFailedContext = new AuthenticationFailedContext(context, scheme, options, message, exception);
                await _events.AuthenticationFailed(authenticationFailedContext);
                return authenticationFailedContext;
            }

            public async Task<RemoteSignOutContext> HandleRemoteSignOut(HttpContext context, AuthenticationScheme scheme, SpidOptions options, LogoutResponseType message)
            {
                var remoteSignOutContext = new RemoteSignOutContext(context, scheme, options, message);
                await _events.RemoteSignOut(remoteSignOutContext);
                return remoteSignOutContext;
            }
        }

        private class RequestHandler
        {
            readonly HttpResponse _response;
            readonly ILogger _logger;
            private readonly ILogHandler _logHandler;

            public RequestHandler(HttpResponse response, ILogger logger, ILogHandler logHandler)
            {
                _response = response;
                _logger = logger;
                _logHandler = logHandler;
            }

            public async Task HandleRequest<T>(T message,
                string messageId,
                X509Certificate2 certificate,
                string signOnUrl,
                RequestMethod method)
                where T : class
            {
                var messageGuid = messageId.Replace("_", string.Empty);

                var unsignedSerializedMessage = SamlHandler.SerializeMessage(message);

                if (method == RequestMethod.Post)
                {
                    var signedSerializedMessage = SamlHandler.SignSerializedDocument(unsignedSerializedMessage, certificate, messageId);
                    var base64SignedSerializedMessage = SamlHandler.ConvertToBase64(signedSerializedMessage);
                    await HandlePostRequest(signedSerializedMessage, base64SignedSerializedMessage, signOnUrl, messageGuid);
                }
                else
                {
                    await HandleRedirectRequest(unsignedSerializedMessage, certificate, signOnUrl, messageGuid);
                }
            }

            private async Task HandlePostRequest(string signedSerializedMessage, string base64SignedSerializedMessage, string url, string messageGuid)
            {
                await _logHandler.LogPostRequest(new PostRequest()
                {
                    SignedMessage = signedSerializedMessage,
                    SAMLRequest = base64SignedSerializedMessage,
                    RelayState = messageGuid,
                    Url = url
                });
                await _response.WriteAsync($"<html><head><title>Login</title></head><body><form id=\"spidform\" action=\"{url}\" method=\"post\">" +
                                          $"<input type=\"hidden\" name=\"SAMLRequest\" value=\"{base64SignedSerializedMessage}\" />" +
                                          $"<input type=\"hidden\" name=\"RelayState\" value=\"{messageGuid}\" />" +
                                          $"<button id=\"btnLogin\" style=\"display: none;\">Login</button>" +
                                          "<script>document.getElementById('btnLogin').click()</script>" +
                                          "</form></body></html>");
            }

            private async Task HandleRedirectRequest(string unsignedSerializedMessage, X509Certificate2 certificate, string url, string messageGuid)
            {
                string redirectUri = await GetRedirectUrl(url, messageGuid, unsignedSerializedMessage, certificate);
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    _logger.MalformedRedirectUri(redirectUri);
                }

                _response.Redirect(redirectUri);
            }

            private async Task<string> GetRedirectUrl(string signOnSignOutUrl, string samlAuthnRequestId, string unsignedSerializedMessage, X509Certificate2 certificate)
            {
                var samlEndpoint = signOnSignOutUrl;

                var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";

                var dict = new Dictionary<string, StringValues>()
                {
                    { "SAMLRequest", CompressString(unsignedSerializedMessage) },
                    { "RelayState", samlAuthnRequestId },
                    { "SigAlg", SamlConst.SignatureMethod }
                };

                var queryStringNoSignature = BuildURLParametersString(dict).Substring(1);

                var signatureQuery = queryStringNoSignature.CreateSignature(certificate);

                dict.Add("Signature", signatureQuery);

                var redirectUri = samlEndpoint + queryStringSeparator + BuildURLParametersString(dict).Substring(1);

                await _logHandler.LogRedirectRequest(new RedirectRequest()
                {
                    SignOnSignOutEndpoint = signOnSignOutUrl,
                    RedirectUri = redirectUri,
                    UncompressedMessage = unsignedSerializedMessage,
                    SAMLRequest = dict["SAMLRequest"],
                    RelayState = dict["RelayState"],
                    SigAlg = dict["SigAlg"],
                    Signature = signatureQuery
                });

                return redirectUri;
            }

            private string CompressString(string value)
            {
                using MemoryStream output = new MemoryStream();
                using (DeflateStream stream = new DeflateStream(output, CompressionMode.Compress))
                {
                    using StreamWriter writer = new StreamWriter(stream, Encoding.UTF8);
                    writer.Write(value);
                }

                return Convert.ToBase64String(output.ToArray());
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

        }
    }


    internal static class AuthenticationPropertiesExtensions
    {
        public static void SetIdentityProviderName(this AuthenticationProperties properties, string name) => properties.Items["IdentityProviderName"] = name;
        public static string GetIdentityProviderName(this AuthenticationProperties properties) => properties.Items["IdentityProviderName"];

        public static void SetAuthenticationRequest(this AuthenticationProperties properties, AuthnRequestType request) =>
            properties.Items["AuthenticationRequest"] = SamlHandler.SerializeMessage(request);
        public static AuthnRequestType GetAuthenticationRequest(this AuthenticationProperties properties) =>
            SamlHandler.DeserializeMessage<AuthnRequestType>(properties.Items["AuthenticationRequest"]);

        public static void SetLogoutRequest(this AuthenticationProperties properties, LogoutRequestType request) =>
            properties.Items["LogoutRequest"] = SamlHandler.SerializeMessage(request);
        public static LogoutRequestType GetLogoutRequest(this AuthenticationProperties properties) =>
            SamlHandler.DeserializeMessage<LogoutRequestType>(properties.Items["LogoutRequest"]);

        public static void SetSubjectNameId(this AuthenticationProperties properties, string subjectNameId) => properties.Items["subjectNameId"] = subjectNameId;
        public static string GetSubjectNameId(this AuthenticationProperties properties) => properties.Items["subjectNameId"];

        public static void SetSessionIndex(this AuthenticationProperties properties, string sessionIndex) => properties.Items["SessionIndex"] = sessionIndex;
        public static string GetSessionIndex(this AuthenticationProperties properties) => properties.Items["SessionIndex"];

        public static void SetCorrelationProperty(this AuthenticationProperties properties, string correlationProperty) => properties.Items[".xsrf"] = correlationProperty;
        public static string GetCorrelationProperty(this AuthenticationProperties properties) => properties.Items[".xsrf"];

        public static void Save(this AuthenticationProperties properties, HttpResponse response, ISecureDataFormat<AuthenticationProperties> encryptor)
        {
            response.Cookies.Append(SpidDefaults.CookieName, encryptor.Protect(properties), new CookieOptions()
            {
                SameSite = SameSiteMode.None,
                Secure = true
            });
        }

        public static void Load(this AuthenticationProperties properties, HttpRequest request, ISecureDataFormat<AuthenticationProperties> encryptor)
        {
            BusinessValidation.ValidationCondition(() => !request.Cookies.ContainsKey(SpidDefaults.CookieName), ErrorLocalization.SpidPropertiesNotFound);
            var cookie = request.Cookies[SpidDefaults.CookieName];
            BusinessValidation.ValidationNotNull(cookie, ErrorLocalization.SpidPropertiesNotFound);
            AuthenticationProperties cookieProperties = encryptor.Unprotect(cookie);
            BusinessValidation.ValidationNotNull(cookieProperties, ErrorLocalization.SpidPropertiesNotFound);
            properties.AllowRefresh = cookieProperties.AllowRefresh;
            properties.ExpiresUtc = cookieProperties.ExpiresUtc;
            properties.IsPersistent = cookieProperties.IsPersistent;
            properties.IssuedUtc = cookieProperties.IssuedUtc;
            foreach (var item in cookieProperties.Items.Where(i => !properties.Items.ContainsKey(i.Key)))
            {
                properties.Items.Add(item);
            }
            foreach (var item in cookieProperties.Parameters.Where(i => !properties.Parameters.ContainsKey(i.Key)))
            {
                properties.Parameters.Add(item);
            }
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
                properties.RedirectUri = cookieProperties.RedirectUri;
        }
    }
}
