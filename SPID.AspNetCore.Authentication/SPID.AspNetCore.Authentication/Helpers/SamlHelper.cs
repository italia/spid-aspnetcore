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
        private static readonly XmlSerializer responseSerializer = new XmlSerializer(typeof(AuthnRequestType));
        private static readonly XmlSerializer entityDescriptorSerializer = new XmlSerializer(typeof(EntityDescriptor));
        private static readonly XmlSerializer logoutRequestSerializer = new XmlSerializer(typeof(LogoutRequestType));
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
        /// <param name="uuid"></param>
        /// <param name="destination"></param>
        /// <param name="consumerServiceURL"></param>
        /// <param name="securityLevel"></param>
        /// <param name="certificate"></param>
        /// <param name="identityProvider"></param>
        /// <returns>Returns a Base64 Encoded String of the SAML request</returns>
        public static (string signedBase64, AuthnRequestType original, string serializedOriginal) BuildAuthnPostRequest(string uuid,
            string entityId,
            ushort? assertionConsumerServiceIndex,
            ushort? attributeConsumingServiceIndex,
            int securityLevel,
            X509Certificate2 certificate,
            IdentityProvider identityProvider)
        {

            BusinessValidation.Argument(uuid, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(uuid)));
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

            AuthnRequestType authnRequest = new AuthnRequestType
            {
                ID = "_" + uuid,
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

            XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
            ns.Add(SamlConst.samlp, SamlConst.Saml2pProtocol);
            ns.Add(SamlConst.saml, SamlConst.Saml2Assertion);

            using StringWriter stringWriter = new StringWriter();
            XmlWriterSettings settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = false,
                Encoding = Encoding.UTF8
            };

            using XmlWriter responseWriter = XmlTextWriter.Create(stringWriter, settings);
            responseSerializer.Serialize(responseWriter, authnRequest, ns);
            responseWriter.Close();

            string samlString = stringWriter.ToString();
            stringWriter.Close();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(samlString);

            XmlElement signature = XmlSigningHelper.SignXMLDoc(doc, certificate, "_" + uuid);
            doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[1]);

            return (Convert.ToBase64String(Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + doc.OuterXml), Base64FormattingOptions.None),
                      authnRequest,
                      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + samlString);
        }

        /// <summary>
        /// Get the IdP Authn Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns>IdpSaml2Response</returns>
        public static Response GetAuthnResponse(string base64Response)
        {
            string idpResponse = null;
            BusinessValidation.Argument(base64Response, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(base64Response)));
            BusinessValidation.ValidationTry(() => idpResponse = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response)), ErrorLocalization.SingleSignOnUrlRequired);
            Response response = null;
            XmlSerializer serializer = new XmlSerializer(typeof(Response));
            try
            {
                using TextReader reader = new StringReader(idpResponse);
                response = (Response)serializer.Deserialize(reader);
                BusinessValidation.ValidationCondition(() => response == null, ErrorLocalization.ResponseNotValid);
                BusinessValidation.ValidationNotNullNotWhitespace(response.InResponseTo, nameof(response.InResponseTo));

                return response;
            }
            catch (Exception)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid);
            }
        }

        public static void ValidateAuthnResponse(this Response response, AuthnRequestType request, EntityDescriptor metadataIdp, bool performFullResponseValidation)
        {
            // Verify signature
            var xmlDoc = response.SerializeToXmlDoc();

            BusinessValidation.ValidationCondition(() => response.Signature == null, ErrorLocalization.ResponseSignatureNotFound);
            BusinessValidation.ValidationCondition(() => response.Assertion?.Signature == null, ErrorLocalization.AssertionSignatureNotFound);
            BusinessValidation.ValidationCondition(() => response.Assertion.Signature.KeyInfo.X509Data.X509Certificate != response.Signature.KeyInfo.X509Data.X509Certificate, ErrorLocalization.AssertionSignatureDifferent);
            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationCondition(() => response.Signature.KeyInfo.X509Data.X509Certificate != metadataIdp.Signature.KeyInfo.X509Data.X509Certificate, ErrorLocalization.ResponseSignatureNotValid);
                BusinessValidation.ValidationCondition(() => response.Assertion?.Signature.KeyInfo.X509Data.X509Certificate != metadataIdp.Signature.KeyInfo.X509Data.X509Certificate, ErrorLocalization.AssertionSignatureNotValid);
            }
            var respSigningCert = @$"
                  -----BEGIN CERTIFICATE-----
                  {response.Signature.KeyInfo.X509Data.X509Certificate}
                  -----END CERTIFICATE-----
                  ";
            using var responseCertificate = new X509Certificate2(Encoding.UTF8.GetBytes(respSigningCert));
            var assertSigningCert = @$"
                  -----BEGIN CERTIFICATE-----
                  {response.Assertion?.Signature.KeyInfo.X509Data.X509Certificate}
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

            BusinessValidation.ValidationNotNullNotEmpty(response.Assertion?.AttributeStatement, nameof(response.Assertion.AttributeStatement));
            BusinessValidation.ValidationCondition(() => response.Assertion.AttributeStatement.Attribute.Count == 0, ErrorLocalization.AttributeNotFound);

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
            var attribute = response.Assertion.AttributeStatement.Attribute;
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

            BusinessValidation.ValidationNotNullNotWhitespace(response.IssueInstant, nameof(response.IssueInstant));
            DateTimeOffset issueIstant = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.IssueInstant, out issueIstant), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.IssueInstant)));

            var issueIstantRequest = DateTimeOffset.Parse(request.IssueInstant);

            BusinessValidation.ValidationCondition(() => (issueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), ErrorLocalization.IssueIstantDifferentFromRequest);

            BusinessValidation.ValidationCondition(() => response.Destination == null, String.Format(ErrorLocalization.NotSpecified, nameof(response.Destination)));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Destination), String.Format(ErrorLocalization.Missing, nameof(response.Destination)));

            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
            {
                BusinessValidation.ValidationCondition(() => !response.Destination.Equals(request.AssertionConsumerServiceURL), string.Format(ErrorLocalization.DifferentFrom, nameof(response.Destination), nameof(request.AssertionConsumerServiceURL)));
            }

            BusinessValidation.ValidationNotNullNotEmpty(response.Status, nameof(response.Status));

            if (!response.Status.StatusCode.Value.Equals(SamlConst.Success, StringComparison.InvariantCultureIgnoreCase))
            {
                if (int.TryParse(response.Status.StatusMessage.Replace("ErrorCode nr", ""), out var errorCode))
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

            BusinessValidation.ValidationCondition(() => response.Issuer == null, ErrorLocalization.IssuerNotSpecified);
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Issuer?.Text), ErrorLocalization.IssuerMissing);
            BusinessValidation.ValidationCondition(() => !response.Issuer.Text.Equals(metadataIdp.EntityID, StringComparison.InvariantCultureIgnoreCase), ErrorLocalization.IssuerDifferentFromEntityId);

            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationNotNullNotWhitespace(response.Issuer.Format, nameof(response.Issuer.Format));
                BusinessValidation.ValidationCondition(() => !response.Issuer.Format.Equals(request.Issuer.Format), ErrorLocalization.IssuerFormatDifferent);
            }

            BusinessValidation.ValidationNotNullNotEmpty(response.Assertion, nameof(response.Assertion));
            BusinessValidation.ValidationCondition(() => response.Assertion.ID == null, string.Format(ErrorLocalization.Missing, "Assertion.ID"));
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.ID, nameof(response.Assertion.ID));
            BusinessValidation.ValidationCondition(() => response.Assertion.Version != SamlConst.Version, string.Format(ErrorLocalization.DifferentFrom, "Assertion.Version", SamlConst.Version));

            BusinessValidation.ValidationCondition(() => response.Assertion.IssueInstant == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.IssueInstant"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.IssueInstant), string.Format(ErrorLocalization.Missing, "Assertion.IssueInstant"));
            DateTimeOffset assertionIssueIstant = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.Assertion.IssueInstant, out assertionIssueIstant), string.Format(ErrorLocalization.FormatNotValid, "Assertion.IssueInstant"));
            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationCondition(() => assertionIssueIstant > issueIstantRequest, ErrorLocalization.IssueIstantAssertionGreaterThanRequest);
                BusinessValidation.ValidationCondition(() => assertionIssueIstant < issueIstantRequest, ErrorLocalization.IssueIstantAssertionLessThanRequest);
            }
            BusinessValidation.ValidationCondition(() => (assertionIssueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), assertionIssueIstant > issueIstantRequest ? ErrorLocalization.IssueIstantAssertionGreaterThanRequest : ErrorLocalization.IssueIstantAssertionLessThanRequest);

            BusinessValidation.ValidationNotNullNotEmpty(response.Assertion.Subject, nameof(response.Assertion.Subject));
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Subject?.NameID?.Text, nameof(response.Assertion.Subject.NameID));
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Subject?.NameID?.Format, nameof(response.Assertion.Subject.NameID.Format));
            BusinessValidation.ValidationCondition(() => !response.Assertion.Subject.NameID.Format.Equals(request.NameIDPolicy.Format), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Subject.NameID.Format)));
            BusinessValidation.ValidationCondition(() => response.Assertion.Subject.NameID.NameQualifier == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.NameID.NameQualifier"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.Subject.NameID.NameQualifier), string.Format(ErrorLocalization.Missing, "Assertion.NameID.NameQualifier"));
            BusinessValidation.ValidationNotNullNotEmpty(response.Assertion.Subject.SubjectConfirmation, nameof(response.Assertion.Subject.SubjectConfirmation));
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Subject.SubjectConfirmation.Method, nameof(response.Assertion.Subject.SubjectConfirmation.Method));
            BusinessValidation.ValidationCondition(() => !response.Assertion.Subject.SubjectConfirmation.Method.Equals(SamlConst.Method), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Subject.SubjectConfirmation.Method)));
            BusinessValidation.ValidationNotNullNotEmpty(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData, nameof(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData));
            BusinessValidation.ValidationCondition(() => response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.Recipient"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient), string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.Recipient"));
            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
            {
                BusinessValidation.ValidationCondition(() => !response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient.Equals(request.AssertionConsumerServiceURL), string.Format(ErrorLocalization.DifferentFrom, "Assertion.SubjectConfirmationData.Recipient", "Request"));
            }
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo, nameof(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo));
            BusinessValidation.ValidationCondition(() => !response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo.Equals(request.ID), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo)));

            BusinessValidation.ValidationCondition(() => response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter), string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            DateTimeOffset notOnOrAfter = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter, out notOnOrAfter), string.Format(ErrorLocalization.FormatNotValid, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            BusinessValidation.ValidationCondition(() => notOnOrAfter < DateTimeOffset.UtcNow, ErrorLocalization.NotOnOrAfterLessThenRequest);

            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Issuer?.Text, nameof(response.Assertion.Issuer));
            BusinessValidation.ValidationCondition(() => !response.Assertion.Issuer.Text.Equals(metadataIdp.EntityID), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Issuer)));
            BusinessValidation.ValidationCondition(() => response.Assertion.Issuer.Format == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.Issuer.Format"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.Issuer.Format), string.Format(ErrorLocalization.Missing, "Assertion.Issuer.Format"));
            BusinessValidation.ValidationCondition(() => !response.Assertion.Issuer.Format.Equals(request.Issuer.Format), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Issuer.Format)));

            BusinessValidation.ValidationCondition(() => response.Assertion.Conditions == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.Conditions"));
            BusinessValidation.ValidationCondition(() => response.Assertion.Conditions.AudienceRestriction == null && string.IsNullOrWhiteSpace(response.Assertion.Conditions.NotBefore) && string.IsNullOrWhiteSpace(response.Assertion.Conditions.NotOnOrAfter), string.Format(ErrorLocalization.Missing, "Assertion.Conditions"));

            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Conditions.NotOnOrAfter, nameof(response.Assertion.Conditions.NotOnOrAfter));
            DateTimeOffset notOnOrAfterCondition = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.Assertion.Conditions.NotOnOrAfter, out notOnOrAfterCondition), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Conditions.NotOnOrAfter)));
            BusinessValidation.ValidationCondition(() => notOnOrAfterCondition < DateTimeOffset.UtcNow, ErrorLocalization.NotOnOrAfterLessThenRequest);


            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Conditions.NotBefore, nameof(response.Assertion.Conditions.NotBefore));
            DateTimeOffset notBefore = new DateTimeOffset();
            BusinessValidation.ValidationCondition(() => !DateTimeOffset.TryParse(response.Assertion.Conditions.NotBefore, out notBefore), string.Format(ErrorLocalization.FormatNotValid, "Assertion.Conditions.NotBefore"));

            BusinessValidation.ValidationCondition(() => notBefore > DateTimeOffset.UtcNow, ErrorLocalization.NotBeforeGreaterThenRequest);

            BusinessValidation.ValidationCondition(() => response.Assertion.Conditions.AudienceRestriction == null, string.Format(ErrorLocalization.Missing, "Assertion.Conditions.AudienceRestriction"));
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Conditions.AudienceRestriction?.Audience, nameof(response.Assertion.Conditions.AudienceRestriction));
            BusinessValidation.ValidationNotNullNotWhitespace(response.Assertion.Conditions.AudienceRestriction.Audience, nameof(response.Assertion.Conditions.AudienceRestriction.Audience));
            BusinessValidation.ValidationCondition(() => !response.Assertion.Conditions.AudienceRestriction.Audience.Equals(request.Issuer.Value), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.Conditions.AudienceRestriction.Audience)));

            BusinessValidation.ValidationCondition(() => response.Assertion.AuthnStatement == null, string.Format(ErrorLocalization.NotSpecified, nameof(response.Assertion.AuthnStatement)));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.AuthnStatement.AuthnInstant) && string.IsNullOrWhiteSpace(response.Assertion.AuthnStatement.SessionIndex) && response.Assertion.AuthnStatement.AuthnContext == null, string.Format(ErrorLocalization.Missing, nameof(response.Assertion.AuthnStatement)));
            BusinessValidation.ValidationNotNullNotEmpty(response.Assertion.AuthnStatement.AuthnContext, nameof(response.Assertion.AuthnStatement.AuthnContext));
            BusinessValidation.ValidationCondition(() => response.Assertion.AuthnStatement.AuthnContext.AuthnContextClassRef == null, string.Format(ErrorLocalization.NotSpecified, "AuthnStatement.AuthnContext.AuthnContextClassRef"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Assertion.AuthnStatement.AuthnContext.AuthnContextClassRef), string.Format(ErrorLocalization.Missing, "AuthnStatement.AuthnContext.AuthnContextClassRef"));
            BusinessValidation.ValidationCondition(() => !response.Assertion.AuthnStatement.AuthnContext.AuthnContextClassRef.Equals(SamlConst.SpidL2), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.AuthnStatement.AuthnContext.AuthnContextClassRef)));

            BusinessValidation.ValidationCondition(() => !listAuthRefValid.Contains(response.Assertion.AuthnStatement.AuthnContext.AuthnContextClassRef), string.Format(ErrorLocalization.ParameterNotValid, nameof(response.Assertion.AuthnStatement.AuthnContext.AuthnContextClassRef)));
            if (performFullResponseValidation)
            {
                BusinessValidation.ValidationCondition(() => !response.Assertion.AttributeStatement.Attribute.All(x => !string.IsNullOrWhiteSpace(x.NameFormat)), string.Format(ErrorLocalization.ParameterNotValid, "Attribute.NameFormat"));
            }
        }


        /// <summary>
        /// Build a signed SAML logout request.
        /// </summary>
        /// <param name="uuid"></param>
        /// <param name="destination"></param>
        /// <param name="consumerServiceURL"></param>
        /// <param name="certificate"></param>
        /// <param name="identityProvider"></param>
        /// <param name="subjectNameId"></param>
        /// <param name="authnStatementSessionIndex"></param>
        /// <returns></returns>
        public static (string, LogoutRequestType) BuildLogoutPostRequest(string uuid, string consumerServiceURL, X509Certificate2 certificate,
                                                    IdentityProvider identityProvider, string subjectNameId, string authnStatementSessionIndex)
        {

            BusinessValidation.Argument(uuid, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(uuid)));
            BusinessValidation.Argument(subjectNameId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(subjectNameId)));
            BusinessValidation.Argument(consumerServiceURL, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(consumerServiceURL)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(consumerServiceURL)));
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

            LogoutRequestType logoutRequest = new LogoutRequestType
            {
                ID = "_" + uuid,
                Version = "2.0",
                IssueInstant = now.ToString(dateTimeFormat),
                Destination = singleLogoutServiceUrl,
                Issuer = new NameIDType
                {
                    Value = consumerServiceURL.Trim(),
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
                    NameQualifier = consumerServiceURL
                },
                Item = new NameIDType
                {
                    SPNameQualifier = consumerServiceURL,
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                    Value = subjectNameId.Replace(subjectNameIdRemoveText, "")
                },
                NotOnOrAfterSpecified = true,
                NotOnOrAfter = now.AddMinutes(10),
                Reason = "urn:oasis:names:tc:SAML:2.0:logout:user",
                SessionIndex = new string[] { authnStatementSessionIndex }
            };

            XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
            ns.Add("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            ns.Add("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

            using StringWriter stringWriter = new StringWriter();
            XmlWriterSettings settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = true,
                Encoding = Encoding.UTF8
            };

            using XmlWriter responseWriter = XmlTextWriter.Create(stringWriter, settings);
            logoutRequestSerializer.Serialize(responseWriter, logoutRequest, ns);
            responseWriter.Close();

            string samlString = stringWriter.ToString();
            stringWriter.Close();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(samlString);

            XmlElement signature = XmlSigningHelper.SignXMLDoc(doc, certificate, "_" + uuid);
            doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[1]);

            return (Convert.ToBase64String(Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + doc.OuterXml)), logoutRequest);
        }

        /// <summary>
        /// Get the IdP Logout Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns></returns>
        public static IdpLogoutResponse GetLogoutResponse(string base64Response)
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

                // Parse XML document
                XDocument xdoc = new XDocument();
                xdoc = XDocument.Parse(idpResponse);

                string destination = VALUE_NOT_AVAILABLE;
                string id = VALUE_NOT_AVAILABLE;
                string inResponseTo = VALUE_NOT_AVAILABLE;
                DateTimeOffset issueInstant = DateTimeOffset.MinValue;
                string version = VALUE_NOT_AVAILABLE;
                string statusCodeValue = VALUE_NOT_AVAILABLE;
                string statusCodeInnerValue = VALUE_NOT_AVAILABLE;
                string statusMessage = VALUE_NOT_AVAILABLE;
                string statusDetail = VALUE_NOT_AVAILABLE;

                // Extract response metadata
                XElement responseElement = xdoc.Elements("{urn:oasis:names:tc:SAML:2.0:protocol}LogoutResponse").Single();
                destination = responseElement.Attribute("Destination").Value;
                id = responseElement.Attribute("ID").Value;
                inResponseTo = responseElement.Attribute("InResponseTo").Value;
                issueInstant = DateTimeOffset.Parse(responseElement.Attribute("IssueInstant").Value);
                version = responseElement.Attribute("Version").Value;

                // Extract Issuer metadata
                string issuer = responseElement.Elements("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").Single().Value.Trim();

                // Extract Status metadata
                XElement StatusElement = responseElement.Descendants("{urn:oasis:names:tc:SAML:2.0:protocol}Status").Single();
                IEnumerable<XElement> statusCodeElements = StatusElement.Descendants("{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode");
                statusCodeValue = statusCodeElements.First().Attribute("Value").Value.Replace("urn:oasis:names:tc:SAML:2.0:status:", "");
                statusCodeInnerValue = statusCodeElements.Count() > 1 ? statusCodeElements.Last().Attribute("Value").Value.Replace("urn:oasis:names:tc:SAML:2.0:status:", "") : VALUE_NOT_AVAILABLE;
                statusMessage = StatusElement.Elements("{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage").SingleOrDefault()?.Value ?? VALUE_NOT_AVAILABLE;
                statusDetail = StatusElement.Elements("{urn:oasis:names:tc:SAML:2.0:protocol}StatusDetail").SingleOrDefault()?.Value ?? VALUE_NOT_AVAILABLE;

                return new IdpLogoutResponse(destination, id, inResponseTo, issueInstant, version, issuer,
                                             statusCodeValue, statusCodeInnerValue, statusMessage, statusDetail);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to read AttributeStatement attributes from SAML2 document.", ex);
            }
        }

        /// <summary>
        /// Check the validity of IdP logout response
        /// </summary>
        /// <param name="idpLogoutResponse"></param>
        /// <param name="samlRequestId"></param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool ValidLogoutResponse(IdpLogoutResponse idpLogoutResponse, string samlRequestId)
        {
            return (idpLogoutResponse.InResponseTo == "_" + samlRequestId);
        }

    }
}
