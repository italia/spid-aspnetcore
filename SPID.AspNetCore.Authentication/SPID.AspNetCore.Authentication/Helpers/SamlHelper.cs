using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Models.IdP;
using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace SPID.AspNetCore.Authentication.Helpers
{
    public static class SamlHelper
    {
        public const string VALUE_NOT_AVAILABLE = "N/A";
        private static readonly Dictionary<Type, XmlSerializer> serializers = new Dictionary<Type, XmlSerializer>
        {
            { typeof(AuthnRequestType), new XmlSerializer(typeof(AuthnRequestType)) },
            { typeof(ResponseType), new XmlSerializer(typeof(ResponseType)) },
            { typeof(LogoutRequestType), new XmlSerializer(typeof(LogoutRequestType)) },
            { typeof(LogoutResponseType), new XmlSerializer(typeof(LogoutResponseType)) },
        };
        private static readonly XmlSerializer entityDescriptorSerializer = new XmlSerializer(typeof(EntityDescriptor));
        private static readonly List<string> listAuthRefValid = new List<string>
        {
            SamlConst.SpidL1,
            SamlConst.SpidL2,
            SamlConst.SpidL3
        };

        public static EntityDescriptor DownloadMetadataIDP(this string urlMetadataIdp)
        {
            string xmlStr;
            BusinessValidation.ValidationNotNullNotWhitespace(urlMetadataIdp, ErrorLocalization.UrlMetadataIDPNull);
            using WebClient wc = new WebClient();
            xmlStr = wc.DownloadString(urlMetadataIdp);

            try
            {
                using TextReader reader = new StringReader(xmlStr);
                return (EntityDescriptor)entityDescriptorSerializer.Deserialize(reader);
            }
            catch (Exception)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid);
            }

        }

        /// <summary>
        /// Build a signed SAML authentication request.
        /// </summary>
        /// <param name="requestId"></param>
        /// <param name="destination"></param>
        /// <param name="consumerServiceURL"></param>
        /// <param name="securityLevel"></param>
        /// <param name="certificate"></param>
        /// <param name="identityProvider"></param>
        /// <returns>Returns a Base64 Encoded String of the SAML request</returns>
        public static AuthnRequestType BuildAuthnPostRequest(string requestId,
            string entityId,
            ushort? assertionConsumerServiceIndex,
            ushort? attributeConsumingServiceIndex,
            int securityLevel,
            X509Certificate2 certificate,
            IdentityProvider identityProvider)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(identityProvider.SingleSignOnServiceUrl), ErrorLocalization.SingleSignOnUrlRequired);

            if (string.IsNullOrWhiteSpace(identityProvider.DateTimeFormat))
            {
                identityProvider.DateTimeFormat = SamlIdentityProviderSettings.DateTimeFormat;
            }

            if (identityProvider.NowDelta == null)
            {
                identityProvider.NowDelta = SamlIdentityProviderSettings.NowDelta;
            }

            string dateTimeFormat = identityProvider.DateTimeFormat;
            double nowDelta = identityProvider.NowDelta.Value;

            DateTimeOffset now = DateTimeOffset.UtcNow;

            return new AuthnRequestType
            {
                ID = "_" + requestId,
                Version = SamlConst.Version,
                IssueInstant = now.AddMinutes(nowDelta).ToString(dateTimeFormat),
                Destination = identityProvider.SingleSignOnServiceUrl,
                ForceAuthn = securityLevel > 1,
                ForceAuthnSpecified = securityLevel > 1,
                Issuer = new NameIDType
                {
                    Value = entityId.Trim(),
                    Format = SamlConst.IssuerFormat,
                    NameQualifier = entityId
                },
                AssertionConsumerServiceIndex = assertionConsumerServiceIndex ?? SamlIdentityProviderSettings.AssertionConsumerServiceIndex,
                AssertionConsumerServiceIndexSpecified = true,
                AttributeConsumingServiceIndex = attributeConsumingServiceIndex ?? SamlIdentityProviderSettings.AttributeConsumingServiceIndex,
                AttributeConsumingServiceIndexSpecified = true,
                NameIDPolicy = new NameIDPolicyType
                {
                    Format = SamlConst.NameIDPolicyFormat,
                    AllowCreate = false,
                    AllowCreateSpecified = false
                },
                Conditions = new ConditionsType
                {
                    NotBefore = now.ToString(dateTimeFormat),
                    NotBeforeSpecified = true,
                    NotOnOrAfter = now.AddMinutes(10).ToString(dateTimeFormat),
                    NotOnOrAfterSpecified = true
                },
                RequestedAuthnContext = new RequestedAuthnContextType
                {
                    Comparison = AuthnContextComparisonType.exact,
                    ComparisonSpecified = true,
                    Items = new string[1]
                    {
                        SamlConst.SpidL2
                    },
                    ItemsElementName = new ItemsChoiceType7[1]
                    {
                        ItemsChoiceType7.AuthnContextClassRef
                    }
                }
            };
        }

        public static string SignRequest<T>(T message, X509Certificate2 certificate, string uuid) where T : class
        {
            var serializedMessage = SerializeMessage(message);

            var doc = new XmlDocument();
            doc.LoadXml(serializedMessage);

            var signature = XmlSigningHelper.SignXMLDoc(doc, certificate, uuid);
            doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[1]);

            return Convert.ToBase64String(
                Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + doc.OuterXml),
                Base64FormattingOptions.None);
        }

        /// <summary>
        /// Get the IdP Authn Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns>IdpSaml2Response</returns>
        public static ResponseType GetAuthnResponse(string base64Response)
        {
            string idpResponse = null;
            BusinessValidation.Argument(base64Response, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(base64Response)));
            BusinessValidation.ValidationTry(() => idpResponse = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response)), ErrorLocalization.SingleSignOnUrlRequired);
            ResponseType response = null;
            try
            {
                response = DeserializeMessage<ResponseType>(idpResponse);

                BusinessValidation.ValidationCondition(() => response == null, ErrorLocalization.ResponseNotValid);
                BusinessValidation.ValidationNotNullNotWhitespace(response.InResponseTo, nameof(response.InResponseTo));

                return response;
            }
            catch (Exception ex)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid);
            }
        }

        public static void ValidateAuthnResponse(this ResponseType response, AuthnRequestType request, EntityDescriptor metadataIdp, bool performFullResponseValidation)
        {
            // Verify signature
            var xmlDoc = response.SerializeToXmlDoc();

            if (!response.Status.StatusCode.Value.Equals(SamlConst.Success, StringComparison.InvariantCultureIgnoreCase))
            {
                if (int.TryParse(response.Status.StatusMessage?.Replace("ErrorCode nr", ""), out var errorCode))
                {
                    switch (errorCode)
                    {
                        case 19:
                            throw new Exception(ErrorLocalization._19);
                        case 20:
                            throw new Exception(ErrorLocalization._20);
                        case 21:
                            throw new Exception(ErrorLocalization._21);
                        case 22:
                            throw new Exception(ErrorLocalization._22);
                        case 23:
                            throw new Exception(ErrorLocalization._23);
                        case 25:
                            throw new Exception(ErrorLocalization._25);
                        default:
                            break;
                    }
                }
                throw new Exception(ErrorLocalization.StatusCodeNotValid);
            }

            BusinessValidation.ValidationCondition(() => response.Signature == null, ErrorLocalization.ResponseSignatureNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion() == null, ErrorLocalization.ResponseAssertionNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion()?.Signature == null, ErrorLocalization.AssertionSignatureNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Signature.KeyInfo.GetX509Data().GetX509Certificate() != response.Signature.KeyInfo.GetX509Data().GetX509Certificate(), ErrorLocalization.AssertionSignatureDifferent);
            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationCondition(() => response.Signature.KeyInfo.GetX509Data().GetX509Certificate() != metadataIdp.Signature.KeyInfo.X509Data.X509Certificate, ErrorLocalization.ResponseSignatureNotValid);
                BusinessValidation.ValidationCondition(() => response.GetAssertion()?.Signature.KeyInfo.GetX509Data().GetX509Certificate() != metadataIdp.Signature.KeyInfo.X509Data.X509Certificate, ErrorLocalization.AssertionSignatureNotValid);
            }
            var respSigningCert = @$"
                  -----BEGIN CERTIFICATE-----
                  {response.Signature.KeyInfo.GetX509Data().GetX509Certificate()}
                  -----END CERTIFICATE-----
                  ";
            using var responseCertificate = new X509Certificate2(Encoding.UTF8.GetBytes(respSigningCert));
            var assertSigningCert = @$"
                  -----BEGIN CERTIFICATE-----
                  {response.GetAssertion()?.Signature.KeyInfo.GetX509Data().GetX509Certificate()}
                  -----END CERTIFICATE-----
                  ";
            using var assertionCertificate = new X509Certificate2(Encoding.UTF8.GetBytes(assertSigningCert));
            var idpSigningCert = @$"
                  -----BEGIN CERTIFICATE-----
                  {metadataIdp.IDPSSODescriptor.KeyDescriptor.KeyInfo.X509Data.X509Certificate}
                  -----END CERTIFICATE-----
                  ";
            using var idpCertificate = new X509Certificate2(Encoding.UTF8.GetBytes(idpSigningCert));

            BusinessValidation.ValidationCondition(() => responseCertificate.Thumbprint != idpCertificate.Thumbprint, ErrorLocalization.ResponseSignatureNotValid);
            BusinessValidation.ValidationCondition(() => assertionCertificate.Thumbprint != idpCertificate.Thumbprint, ErrorLocalization.AssertionSignatureNotValid);

            BusinessValidation.ValidationCondition(() => response.Version != SamlConst.Version, ErrorLocalization.VersionNotValid);
            BusinessValidation.ValidationNotNullNotWhitespace(response.ID, nameof(response.ID));

            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion()?.GetAttributeStatement(), nameof(ErrorFields.Assertion));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement().GetAttributes().Count() == 0, ErrorLocalization.AttributeNotFound);

            var listAttribute = new List<string>
            {
                SamlConst.fiscalNumber,
                SamlConst.digitalAddress,
                SamlConst.name,
                SamlConst.familyName,
                SamlConst.email,
                SamlConst.address,
                SamlConst.companyName,
                SamlConst.countyOfBirth,
                SamlConst.dateOfBirth,
                SamlConst.expirationDate,
                SamlConst.fiscalNumber,
                SamlConst.gender,
                SamlConst.idCard,
                SamlConst.ivaCode,
                SamlConst.mobilePhone,
                SamlConst.placeOfBirth,
                SamlConst.registeredOffice,
                SamlConst.spidCode,
            };

            //Reminder la condizione startWith("urn") e l'attributo FriendlyName è stato introdotto per gestire le response proveniente da ionoi bologna (shibbolet)
            var attribute = response.GetAssertion().GetAttributeStatement().GetAttributes();
            List<string> attributeNames = new List<string>();
            attributeNames.AddRange(attribute.Where(x => !string.IsNullOrWhiteSpace(x.Name) && !x.Name.StartsWith("urn")).Select(x => x.Name).ToList());
            BusinessValidation.ValidationCondition(() => attributeNames.Count() == 0, ErrorLocalization.AttributeRequiredNotFound);
            if (attributeNames.Count() > 0)
            {
                BusinessValidation.ValidationCondition(() => attributeNames.Any(x => !listAttribute.Contains(x)), ErrorLocalization.AttributeRequiredNotFound);
            }
            else
            {
                listAttribute.Add(SamlConst.firstname);
                listAttribute.Add(SamlConst.surname);
                listAttribute.Add(SamlConst.mail);
                attributeNames.AddRange(attribute.Where(x => !string.IsNullOrWhiteSpace(x.FriendlyName)).Select(x => x.FriendlyName).ToList());
                BusinessValidation.ValidationCondition(() => attributeNames.Count() == 0, ErrorLocalization.AttributeRequiredNotFound);
                if (attributeNames.Count() > 0)
                {
                    BusinessValidation.ValidationCondition(() => listAttribute.All(x => !attributeNames.Contains(x)), ErrorLocalization.AttributeRequiredNotFound);
                }
            }

            DateTimeOffset issueIstant = new DateTimeOffset(response.IssueInstant);
            var issueIstantRequest = DateTimeOffset.Parse(request.IssueInstant);

            BusinessValidation.ValidationCondition(() => (issueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), ErrorLocalization.IssueIstantDifferentFromRequest);

            BusinessValidation.ValidationNotNullNotWhitespace(response.Destination, nameof(response.Destination));
            BusinessValidation.ValidationCondition(() => !response.Destination.Equals(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient, StringComparison.OrdinalIgnoreCase), ErrorLocalization.InvalidDestination);

            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
            {
                BusinessValidation.ValidationCondition(() => !response.Destination.Equals(request.AssertionConsumerServiceURL), string.Format(ErrorLocalization.DifferentFrom, nameof(response.Destination), nameof(request.AssertionConsumerServiceURL)));
            }

            BusinessValidation.ValidationNotNullNotEmpty(response.Status, nameof(response.Status));

            BusinessValidation.ValidationCondition(() => response.Issuer == null, ErrorLocalization.IssuerNotSpecified);
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Issuer?.Value), ErrorLocalization.IssuerMissing);
            BusinessValidation.ValidationCondition(() => !response.Issuer.Value.Equals(metadataIdp.EntityID, StringComparison.InvariantCultureIgnoreCase), ErrorLocalization.IssuerDifferentFromEntityId);

            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationNotNullNotWhitespace(response.Issuer.Format, nameof(response.Issuer.Format));
                BusinessValidation.ValidationCondition(() => !response.Issuer.Format.Equals(request.Issuer.Format), ErrorLocalization.IssuerFormatDifferent);
            }

            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion(), nameof(ErrorFields.Assertion));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().ID == null, string.Format(ErrorLocalization.Missing, nameof(Assertion.ID)));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().ID, nameof(ErrorFields.ID));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Version != SamlConst.Version, string.Format(ErrorLocalization.DifferentFrom, nameof(Assertion.Version), SamlConst.Version));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().IssueInstant == null, string.Format(ErrorLocalization.NotSpecified, nameof(ErrorFields.IssueInstant)));
            DateTimeOffset assertionIssueIstant = response.GetAssertion().IssueInstant;
            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationCondition(() => assertionIssueIstant > issueIstantRequest, ErrorLocalization.IssueIstantAssertionGreaterThanRequest);
                BusinessValidation.ValidationCondition(() => assertionIssueIstant < issueIstantRequest, ErrorLocalization.IssueIstantAssertionLessThanRequest);
            }
            BusinessValidation.ValidationCondition(() => (assertionIssueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), assertionIssueIstant > issueIstantRequest ? ErrorLocalization.IssueIstantAssertionGreaterThanRequest : ErrorLocalization.IssueIstantAssertionLessThanRequest);

            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject, nameof(ErrorFields.Subject));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject?.GetNameID()?.Value, nameof(ErrorFields.NameID));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject?.GetNameID()?.Format, nameof(ErrorFields.Format));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetNameID().Format.Equals(request.NameIDPolicy.Format), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.Format)));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetNameID().NameQualifier == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.NameID.NameQualifier"));
            BusinessValidation.ValidationCondition(() => String.IsNullOrWhiteSpace(response.GetAssertion().Subject.GetNameID().NameQualifier), string.Format(ErrorLocalization.Missing, "Assertion.NameID.NameQualifier"));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject.GetSubjectConfirmation(), nameof(ErrorFields.SubjectConfirmation));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject.GetSubjectConfirmation().Method, nameof(ErrorFields.Method));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().Method.Equals(SamlConst.Method), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.Method)));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData, nameof(ErrorFields.SubjectConfirmationData));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.Recipient"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient), string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.Recipient"));
            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
            {
                BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient.Equals(request.AssertionConsumerServiceURL), string.Format(ErrorLocalization.DifferentFrom, "Assertion.SubjectConfirmationData.Recipient", "Request"));
            }
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.InResponseTo, nameof(ErrorFields.InResponseTo));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.InResponseTo.Equals(request.ID), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.InResponseTo)));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter == DateTime.MinValue, string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            DateTimeOffset notOnOrAfter = new DateTimeOffset(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter);
            BusinessValidation.ValidationCondition(() => notOnOrAfter < DateTimeOffset.UtcNow, ErrorLocalization.NotOnOrAfterLessThenRequest);

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Issuer?.Value, nameof(ErrorFields.Issuer));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Issuer.Value.Equals(metadataIdp.EntityID), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.Issuer)));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Issuer.Format == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.Issuer.Format"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().Issuer.Format), string.Format(ErrorLocalization.Missing, "Assertion.Issuer.Format"));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Issuer.Format.Equals(request.Issuer.Format), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.Format)));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.Conditions"));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions.GetAudienceRestriction() == null && string.IsNullOrWhiteSpace(response.GetAssertion().Conditions.NotBefore) && string.IsNullOrWhiteSpace(response.GetAssertion().Conditions.NotOnOrAfter), string.Format(ErrorLocalization.Missing, "Assertion.Conditions"));

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.NotOnOrAfter, nameof(ErrorFields.NotOnOrAfter));
            DateTimeOffset notOnOrAfterCondition = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.GetAssertion().Conditions.NotOnOrAfter, out notOnOrAfterCondition), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.NotOnOrAfter)));
            BusinessValidation.ValidationCondition(() => notOnOrAfterCondition < DateTimeOffset.UtcNow, ErrorLocalization.NotOnOrAfterLessThenRequest);


            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.NotBefore, nameof(ErrorFields.NotBefore));
            DateTimeOffset notBefore = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.GetAssertion().Conditions.NotBefore, out notBefore), string.Format(ErrorLocalization.FormatNotValid, "Assertion.Conditions.NotBefore"));

            BusinessValidation.ValidationCondition(() => notBefore > DateTimeOffset.UtcNow, ErrorLocalization.NotBeforeGreaterThenRequest);

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions.GetAudienceRestriction() == null, string.Format(ErrorLocalization.Missing, "Assertion.Conditions.AudienceRestriction"));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.GetAudienceRestriction().Audience.First(), nameof(ErrorFields.Audience));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Conditions.GetAudienceRestriction().Audience.First().Equals(request.Issuer.Value), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.Audience)));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement() == null, string.Format(ErrorLocalization.NotSpecified, nameof(ErrorFields.AuthnStatement)));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement().AuthnInstant == DateTime.MinValue && string.IsNullOrWhiteSpace(response.GetAssertion().GetAuthnStatement().SessionIndex) && response.GetAssertion().GetAuthnStatement().AuthnContext == null, string.Format(ErrorLocalization.Missing, nameof(ErrorFields.AuthnStatement)));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().GetAuthnStatement().AuthnContext, nameof(ErrorFields.AuthnContext));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef() == null, string.Format(ErrorLocalization.NotSpecified, "AuthnStatement.AuthnContext.AuthnContextClassRef"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef()), string.Format(ErrorLocalization.Missing, "AuthnStatement.AuthnContext.AuthnContextClassRef"));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef().Equals(SamlConst.SpidL2), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.AuthnContextClassRef)));

            BusinessValidation.ValidationCondition(() => !listAuthRefValid.Contains(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef()), string.Format(ErrorLocalization.ParameterNotValid, nameof(ErrorFields.AuthnContextClassRef)));
            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationCondition(() => !response.GetAssertion().GetAttributeStatement().GetAttributes().All(x => !string.IsNullOrWhiteSpace(x.NameFormat)), string.Format(ErrorLocalization.ParameterNotValid, "Attribute.NameFormat"));
            }
        }


        /// <summary>
        /// Build a signed SAML logout request.
        /// </summary>
        /// <param name="requestId"></param>
        /// <param name="destination"></param>
        /// <param name="consumerServiceURL"></param>
        /// <param name="certificate"></param>
        /// <param name="identityProvider"></param>
        /// <param name="subjectNameId"></param>
        /// <param name="authnStatementSessionIndex"></param>
        /// <returns></returns>
        public static LogoutRequestType BuildLogoutPostRequest(string requestId, string consumerServiceURL, X509Certificate2 certificate,
           IdentityProvider identityProvider, string subjectNameId, string authnStatementSessionIndex)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(subjectNameId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(subjectNameId)));
            BusinessValidation.Argument(consumerServiceURL, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(consumerServiceURL)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));

            if (string.IsNullOrWhiteSpace(identityProvider.DateTimeFormat))
            {
                identityProvider.DateTimeFormat = SamlIdentityProviderSettings.DateTimeFormat;
            }

            if (identityProvider.NowDelta == null)
            {
                identityProvider.NowDelta = SamlIdentityProviderSettings.NowDelta;
            }

            if (string.IsNullOrWhiteSpace(identityProvider.SingleSignOutServiceUrl))
            {
                throw new ArgumentNullException("The LogoutServiceUrl of the identity provider is null or empty.");
            }

            string dateTimeFormat = identityProvider.DateTimeFormat;
            string subjectNameIdRemoveText = identityProvider.SubjectNameIdRemoveText;
            string singleLogoutServiceUrl = identityProvider.SingleSignOutServiceUrl;

            DateTime now = DateTime.UtcNow;

            return new LogoutRequestType
            {
                ID = "_" + requestId,
                Version = "2.0",
                IssueInstant = now.ToString(dateTimeFormat),
                Destination = singleLogoutServiceUrl,
                Issuer = new NameIDType
                {
                    Value = consumerServiceURL.Trim(),
                    Format = SamlConst.IssuerFormat,
                    NameQualifier = consumerServiceURL
                },
                Item = new NameIDType
                {
                    NameQualifier = consumerServiceURL,
                    Format = SamlConst.NameIDPolicyFormat,
                    Value = subjectNameIdRemoveText == null ? subjectNameId : subjectNameId.Replace(subjectNameIdRemoveText, String.Empty)
                },
                NotOnOrAfterSpecified = true,
                NotOnOrAfter = now.AddMinutes(10),
                Reason = SamlConst.LogoutUserProtocol,
                SessionIndex = new string[] { authnStatementSessionIndex }
            };

        }

        /// <summary>
        /// Get the IdP Logout Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns></returns>
        public static LogoutResponseType GetLogoutResponse(string base64Response)
        {
            string idpResponse;

            if (String.IsNullOrEmpty(base64Response))
            {
                throw new ArgumentNullException("The base64Response parameter can't be null or empty.");
            }

            try
            {
                idpResponse = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response));
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to converto base64 response to ascii string.", ex);
            }

            try
            {
                // Verify signature
                XmlDocument xml = new XmlDocument { PreserveWhitespace = true };
                xml.LoadXml(idpResponse);
                if (!XmlSigningHelper.VerifySignature(xml))
                {
                    throw new Exception("Unable to verify the signature of the IdP response.");
                }

                return DeserializeMessage<LogoutResponseType>(idpResponse);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to read AttributeStatement attributes from SAML2 document.", ex);
            }
        }

        /// <summary>
        /// Check the validity of IdP logout response
        /// </summary>
        /// <param name="response"></param>
        /// <param name="request"></param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool ValidateLogoutResponse(StatusResponseType response, LogoutRequestType request)
        {
            return (response.InResponseTo == request.ID);
        }

        public static string SerializeMessage<T>(T message) where T : class
        {
            var serializer = serializers[typeof(T)];
            var ns = new XmlSerializerNamespaces();
            ns.Add(SamlConst.samlp, SamlConst.Saml2pProtocol);
            ns.Add(SamlConst.saml, SamlConst.Saml2Assertion);

            var settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = false,
                Encoding = Encoding.UTF8
            };

            using var stringWriter = new StringWriter();
            using var responseWriter = XmlTextWriter.Create(stringWriter, settings);
            serializer.Serialize(responseWriter, message, ns);
            return stringWriter.ToString();
        }

        public static T DeserializeMessage<T>(string message) where T : class
        {
            var serializer = serializers[typeof(T)];
            using var stringReader = new StringReader(message);
            return serializer.Deserialize(stringReader) as T;
        }

        private class ErrorFields
        {
            public static object Assertion;
            public static object AttributeStatement;
            public static object ID;
            public static object IssueInstant;
            public static object Subject;
            public static object NameID;
            public static object Format;
            public static object SubjectConfirmation;
            public static object Method;
            public static object SubjectConfirmationData;
            public static object InResponseTo;
            public static object Issuer;
            public static object NotOnOrAfter;
            public static object NotBefore;
            public static object AudienceRestriction;
            public static object Audience;
            public static object AuthnStatement;
            public static object AuthnContext;
            public static object AuthnContextClassRef;
        }
    }
}
