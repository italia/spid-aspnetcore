using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace SPID.AspNetCore.Authentication.Saml
{
    internal static class SamlHandler
    {
        private static readonly Dictionary<Type, XmlSerializer> serializers = new Dictionary<Type, XmlSerializer>
        {
            { typeof(AuthnRequestType), new XmlSerializer(typeof(AuthnRequestType)) },
            { typeof(ResponseType), new XmlSerializer(typeof(ResponseType)) },
            { typeof(LogoutRequestType), new XmlSerializer(typeof(LogoutRequestType)) },
            { typeof(LogoutResponseType), new XmlSerializer(typeof(LogoutResponseType)) },
            { typeof(Aggregated.EntityDescriptorType), new XmlSerializer(typeof(Aggregated.EntityDescriptorType)) },
            { typeof(SP.EntityDescriptorType), new XmlSerializer(typeof(SP.EntityDescriptorType)) },
            { typeof(SPAv29.EntityDescriptorType), new XmlSerializer(typeof(SPAv29.EntityDescriptorType)) },
        };
        private static readonly List<string> listAuthRefValid = new List<string>
        {
            SamlConst.SpidL + "1",
            SamlConst.SpidL + "2",
            SamlConst.SpidL + "3"
        };

        private const int ClockSkewInMinutes = 10;

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
        public static AuthnRequestType GetAuthnRequest(string requestId,
            string entityId,
            string assertionConsumerServiceURL,
            ushort? assertionConsumerServiceIndex,
            ushort attributeConsumingServiceIndex,
            X509Certificate2 certificate,
            int securityLevel,
            RequestMethod requestMethod,
            IdentityProvider identityProvider)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(identityProvider.GetSingleSignOnServiceUrl(requestMethod)), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.SingleSignOnUrlRequired, SpidErrorCode.SSOUrlRequired));

            if (string.IsNullOrWhiteSpace(identityProvider.DateTimeFormat))
            {
                identityProvider.DateTimeFormat = SamlDefaultSettings.DateTimeFormat;
            }

            if (identityProvider.NowDelta == null)
            {
                identityProvider.NowDelta = SamlDefaultSettings.NowDelta;
            }

            string dateTimeFormat = identityProvider.DateTimeFormat;
            double nowDelta = identityProvider.NowDelta.Value;

            DateTimeOffset now = DateTimeOffset.UtcNow;

            return new AuthnRequestType
            {
                ID = "_" + requestId,
                Version = SamlConst.Version,
                IssueInstant = now.AddMinutes(nowDelta).ToString(dateTimeFormat),
                Destination = identityProvider.GetSingleSignOnServiceUrl(requestMethod),
                ForceAuthn = true,
                ForceAuthnSpecified = true,
                Issuer = new NameIDType
                {
                    Value = entityId.Trim(),
                    Format = SamlConst.IssuerFormat,
                    NameQualifier = entityId
                },
                AssertionConsumerServiceURL = assertionConsumerServiceURL,
                AssertionConsumerServiceIndex = assertionConsumerServiceIndex ?? SamlDefaultSettings.AssertionConsumerServiceIndex,
                AssertionConsumerServiceIndexSpecified = assertionConsumerServiceIndex.HasValue,
                AttributeConsumingServiceIndex = attributeConsumingServiceIndex,
                AttributeConsumingServiceIndexSpecified = true,
                NameIDPolicy = new NameIDPolicyType
                {
                    Format = SamlConst.NameIDPolicyFormat,
                    AllowCreate = false,
                    AllowCreateSpecified = false
                },
                Conditions = new ConditionsType
                {
                    NotBefore = now.AddMinutes(-ClockSkewInMinutes).ToString(dateTimeFormat),
                    NotBeforeSpecified = true,
                    NotOnOrAfter = now.AddMinutes(ClockSkewInMinutes).ToString(dateTimeFormat),
                    NotOnOrAfterSpecified = true
                },
                RequestedAuthnContext = new RequestedAuthnContextType
                {
                    Comparison = AuthnContextComparisonType.minimum,
                    ComparisonSpecified = true,
                    Items = new string[1]
                    {
                        SamlConst.SpidL + securityLevel
                    },
                    ItemsElementName = new ItemsChoiceType7[1]
                    {
                        ItemsChoiceType7.AuthnContextClassRef
                    }
                }
            };
        }

        /// <summary>
        /// Signs the request.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="message">The message.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="uuid">The UUID.</param>
        /// <returns></returns>
        public static string SignSerializedDocument(string serializedDocument, X509Certificate2 certificate, string uuid)
        {
            return SignDocumentInternal(serializedDocument, certificate, uuid, 1);
        }

        public static string SignSerializedMetadata(string serializedDocument, X509Certificate2 certificate, string uuid)
        {
            return SignDocumentInternal(serializedDocument, certificate, uuid, 0);
        }

        private static string SignDocumentInternal(string serializedDocument, X509Certificate2 certificate, string uuid, int childIndex)
        {
            var doc = new XmlDocument();
            doc.LoadXml(serializedDocument);

            var signature = XmlHelpers.SignXMLDoc(doc, certificate, uuid, SamlConst.SignatureMethod, SamlConst.DigestMethod);
            doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[childIndex]);

            return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + doc.OuterXml;
        }

        public static string ConvertToBase64(string message)
        {
            return Convert.ToBase64String(
                   Encoding.UTF8.GetBytes(message),
                   Base64FormattingOptions.None);
        }

        /// <summary>
        /// Get the IdP Authn Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns>IdpSaml2Response</returns>
        public static ResponseType GetAuthnResponse(string serializedResponse)
        {
            BusinessValidation.Argument(serializedResponse, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(serializedResponse)));
            ResponseType response = null;
            try
            {
                response = DeserializeMessage<ResponseType>(serializedResponse);

                BusinessValidation.ValidationCondition(() => response == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.ResponseNotValid, SpidErrorCode.ResponseMancante));

                return response;
            }
            catch (Exception ex)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid, ex);
            }
        }

        /// <summary>
        /// Validates the authn response.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="request">The request.</param>
        /// <param name="identityProvider">The IdentityProvider.</param>
        /// <exception cref="Exception">
        /// </exception>
        public static void ValidateAuthnResponse(this ResponseType response, AuthnRequestType request, IdentityProvider identityProvider, string serializedResponse)
        {
            // Verify signature
            var xmlDoc = new XmlDocument() { PreserveWhitespace = true };
            xmlDoc.LoadXml(serializedResponse);

            BusinessValidation.ValidationCondition(() => response.Status == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.StatusNotValid, SpidErrorCode.ResponseStatusMancante));
            BusinessValidation.ValidationCondition(() => response.Status.StatusCode == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.StatusCodeNotValid, SpidErrorCode.ResponseStatusCodeMancante));

            if (!response.Status.StatusCode.Value.Equals(SamlConst.Success, StringComparison.InvariantCultureIgnoreCase))
            {
                if (int.TryParse(response.Status.StatusMessage?.Replace("ErrorCode nr", ""), out var errorCode))
                {
                    switch (errorCode)
                    {
                        case 8:
                            throw new SpidException(ErrorLocalization._08, SpidErrorCode.SAMLInvalid);
                        case 9:
                            throw new SpidException(ErrorLocalization._09, SpidErrorCode.ResponseVersionNoDue);
                        case 11:
                            throw new SpidException(ErrorLocalization._11, SpidErrorCode.ResponseIdMancante);
                        case 12:
                            throw new SpidException(ErrorLocalization._12, SpidErrorCode.AssertionAuthStatementAuthnContextNonSpec);
                        case 13:
                            throw new SpidException(ErrorLocalization._13, SpidErrorCode.ResponseIssueInstantNonSpec);
                        case 14:
                            throw new SpidException(ErrorLocalization._14, SpidErrorCode.ResponseDestinationNonSpec);
                        case 15:
                            throw new SpidException(ErrorLocalization._15, SpidErrorCode.IsPassiveTrue);
                        case 16:
                            throw new SpidException(ErrorLocalization._16, SpidErrorCode.ResponseDestinationDiversoDaAssertionConsumerServiceURL);
                        case 17:
                            throw new SpidException(ErrorLocalization._17, SpidErrorCode.AssertionNameIdFormatNonSpec);
                        case 18:
                            throw new SpidException(ErrorLocalization._18, SpidErrorCode.AttributeConsumerServiceIndexNonCorretto);
                        case 19:
                            throw new SpidException(ErrorLocalization._19, SpidErrorCode.Anomalia19);
                        case 20:
                            throw new SpidException(ErrorLocalization._20, SpidErrorCode.Anomalia20);
                        case 21:
                            throw new SpidException(ErrorLocalization._21, SpidErrorCode.Anomalia21);
                        case 22:
                            throw new SpidException(ErrorLocalization._22, SpidErrorCode.Anomalia22);
                        case 23:
                            throw new SpidException(ErrorLocalization._23, SpidErrorCode.Anomalia23);
                        case 25:
                            throw new SpidException(ErrorLocalization._25, SpidErrorCode.Anomalia25);
                        case 30:
                            throw new SpidException(ErrorLocalization._30, SpidErrorCode.Anomalia30);
                        default:
                            break;
                    }
                }
                throw new SpidException(ErrorLocalization.StatusCodeNotValid, SpidErrorCode.ResponseStatusCodeNonSpec);
            }

            BusinessValidation.ValidationCondition(() => response.Signature == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.ResponseSignatureNotFound, SpidErrorCode.ResponseNonFirmata));
            BusinessValidation.ValidationCondition(() => response?.GetAssertion() == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.ResponseAssertionNotFound, SpidErrorCode.ResponseAssertionMancante));
            BusinessValidation.ValidationCondition(() => response.GetAssertion()?.Signature == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AssertionSignatureNotFound, SpidErrorCode.ResponseAssertionNonFirmata));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Signature.KeyInfo?.GetX509Data()?.GetBase64X509Certificate() != response.Signature.KeyInfo?.GetX509Data()?.GetBase64X509Certificate(), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AssertionSignatureDifferent, SpidErrorCode.AssertionFirmaDiversa));
            //var metadataXmlDoc = metadataIdp.SerializeToXmlDoc();
            BusinessValidation.ValidationCondition(() => !XmlHelpers.VerifySignature(xmlDoc, identityProvider), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.InvalidSignature, SpidErrorCode.ResponseFirmaNonValida));

            BusinessValidation.ValidationCondition(() => response.Version != SamlConst.Version, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.VersionNotValid, SpidErrorCode.ResponseVersionNoDue));
            BusinessValidation.ValidationNotNullNotWhitespace(response.ID, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, nameof(response.ID)), SpidErrorCode.ResponseIdNonSpecificato));

            BusinessValidation.ValidationNotNull(response.GetAssertion()?.GetAttributeStatement(), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.Assertion), SpidErrorCode.ResponseAssertionMancante));//non viene testata questa cosa, la mantengo come errore assetion mancante
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement()?.GetAttributes()?.Count() == 0, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AttributeNotFound, SpidErrorCode.AssertionAttributeStatementNoAttribute));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement()?.GetAttributes()?.Any(a => a.AttributeValue == null) ?? false, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AttributeNotFound, SpidErrorCode.AssertionAttributeStatementNoAttribute));

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
                SamlConst.companyFiscalNumber,
                SamlConst.domicileStreetAddress,
                SamlConst.domicileProvince,
                SamlConst.domicilePostalCode,
                SamlConst.domicileNation,
                SamlConst.domicileMunicipality
            };

            var attribute = response.GetAssertion().GetAttributeStatement().GetAttributes();
            List<string> attributeNames = new List<string>();
            attributeNames.AddRange(attribute.Where(x => !string.IsNullOrWhiteSpace(x.Name) && !x.Name.StartsWith("urn")).Select(x => x.Name).ToList());
            BusinessValidation.ValidationCondition(() => attributeNames.Count() == 0, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AttributeRequiredNotFound, SpidErrorCode.AttributiRichiestiMancanti));
            if (attributeNames.Count() > 0)
            {
                BusinessValidation.ValidationCondition(() => attributeNames.Any(x => !listAttribute.Contains(x)), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AttributeRequiredNotFound, SpidErrorCode.AttributiRichiestiMancanti));
            }
            else
            {
                listAttribute.Add(SamlConst.firstname);
                listAttribute.Add(SamlConst.surname);
                listAttribute.Add(SamlConst.mail);
                attributeNames.AddRange(attribute.Where(x => !string.IsNullOrWhiteSpace(x.FriendlyName)).Select(x => x.FriendlyName).ToList());
                BusinessValidation.ValidationCondition(() => attributeNames.Count() == 0, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AttributeRequiredNotFound, SpidErrorCode.AttributiRichiestiMancanti));
                if (attributeNames.Count() > 0)
                {
                    BusinessValidation.ValidationCondition(() => listAttribute.All(x => !attributeNames.Contains(x)), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.AttributeRequiredNotFound, SpidErrorCode.AttributiRichiestiMancanti));
                }
            }

            BusinessValidation.ValidationCondition(() => response.IssueInstant == default, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssueInstantMissing, SpidErrorCode.ResponseIssueInstantMancante));
            DateTimeOffset issueIstant = new DateTimeOffset(response.IssueInstant);
            var issueIstantRequest = DateTimeOffset.Parse(request.IssueInstant);

            BusinessValidation.ValidationCondition(() => (issueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssueIstantDifferentFromRequest, SpidErrorCode.ResponseIssueInstantNonCorretto));

            BusinessValidation.ValidationNotNullNotWhitespace(response.InResponseTo, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, nameof(response.InResponseTo)), SpidErrorCode.ResponseInResponseToNonSpec));

            BusinessValidation.ValidationNotNullNotWhitespace(response.Destination, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, nameof(response.Destination)), SpidErrorCode.ResponseDestinationNonSpec));

            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
                BusinessValidation.ValidationCondition(() => !response.Destination.Equals(request.AssertionConsumerServiceURL), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.DifferentFrom, nameof(response.Destination), nameof(request.AssertionConsumerServiceURL)), SpidErrorCode.ResponseDestinationDiversoDaAssertionConsumerServiceURL));

            BusinessValidation.ValidationNotNullNotEmpty(response.Status, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, nameof(response.Status)), SpidErrorCode.ResponseStatusMancante));

            BusinessValidation.ValidationCondition(() => response.Issuer == null, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssuerNotSpecified, SpidErrorCode.ResponseIssuerNonSpec));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Issuer?.Value), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssuerMissing, SpidErrorCode.ResponseIssuerMancante));
            BusinessValidation.ValidationCondition(() => !response.Issuer.Value.Equals(identityProvider.EntityId, StringComparison.InvariantCultureIgnoreCase), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssuerDifferentFromEntityId, SpidErrorCode.ResponseIssuerDiversoDaIdP));

            BusinessValidation.ValidationCondition(() => !string.IsNullOrWhiteSpace(response.Issuer.Format) && !response.Issuer.Format.Equals(SamlConst.IssuerFormat), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssuerFormatDifferent, SpidErrorCode.ResponseIssuerFormatDiverso));

            BusinessValidation.ValidationNotNullNotEmpty(response?.GetAssertion(), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.Assertion), SpidErrorCode.ResponseAssertionMancante));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().ID == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.ID), SpidErrorCode.AssertionIdNonSpec));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().ID, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.ID), SpidErrorCode.AssertionIdNonSpec));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Version != SamlConst.Version, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.DifferentFrom, ErrorFields.Version, SamlConst.Version), SpidErrorCode.AssertionVersionNoDue));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().IssueInstant == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.IssueInstant), SpidErrorCode.AssertionIssueInstantNonSpec));
            DateTimeOffset assertionIssueIstant = response.GetAssertion().IssueInstant;

            BusinessValidation.ValidationCondition(() => assertionIssueIstant > issueIstantRequest.AddMinutes(10), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssueIstantAssertionGreaterThanRequest, SpidErrorCode.AssertionIssueInstantPostRequest));
            BusinessValidation.ValidationCondition(() => assertionIssueIstant < issueIstantRequest, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.IssueIstantAssertionLessThanRequest, SpidErrorCode.AssertionIssueInstantPreRequest));

            BusinessValidation.ValidationCondition(() => (assertionIssueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), new SpidException(ErrorLocalization.GenericMessage, assertionIssueIstant > issueIstantRequest ? ErrorLocalization.IssueIstantAssertionGreaterThanRequest : ErrorLocalization.IssueIstantAssertionLessThanRequest, assertionIssueIstant > issueIstantRequest ? SpidErrorCode.AssertionIssueInstantPostRequest : SpidErrorCode.AssertionIssueInstantPreRequest));

            BusinessValidation.ValidationNotNull(response.GetAssertion().Subject, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.Subject), SpidErrorCode.AssertionSubjectNonSpec));
            BusinessValidation.ValidationNotNull(response.GetAssertion().Subject?.Items, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.Subject), SpidErrorCode.AssertionSubjectMancante));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject?.GetNameID()?.Value, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.NameID), SpidErrorCode.AssertionNameIdMancante));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject?.GetNameID()?.Format, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.Format), SpidErrorCode.AssertionNameIdFormatMancante));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetNameID().Format.Equals(request.NameIDPolicy.Format), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Format), SpidErrorCode.AssertionNameIdFormatDiverso));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetNameID().NameQualifier == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, "Assertion.NameID.NameQualifier"), SpidErrorCode.AssertionNameIdNameQualifierNonSpec));
            BusinessValidation.ValidationCondition(() => String.IsNullOrWhiteSpace(response.GetAssertion().Subject.GetNameID().NameQualifier), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "Assertion.NameID.NameQualifier"), SpidErrorCode.AssertionNameIdNameQualifierMancante));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject.GetSubjectConfirmation(), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.SubjectConfirmation), SpidErrorCode.AssertionSubjectConfirmationMancante));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject.GetSubjectConfirmation().Method, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.Method), SpidErrorCode.AssertionSubjectConfirmationMethodMancante));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().Method.Equals(SamlConst.Method), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Method), SpidErrorCode.AssertionSubjectConfirmationMethodDiverso));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.SubjectConfirmationData), SpidErrorCode.AssertionSubjectConfirmationDataMancante));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.Recipient"), SpidErrorCode.AssertionSubjectConfirmationDataRecipientNonSpec));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.Recipient"), SpidErrorCode.AssertionSubjectConfirmationDataRecipientMancante));
            BusinessValidation.ValidationCondition(() => !response.Destination.Equals(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient, StringComparison.OrdinalIgnoreCase), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.InvalidDestination, SpidErrorCode.ResponseDestinationDiversoDaAssertionConsumerServiceURL));

            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
                BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient.Equals(request.AssertionConsumerServiceURL), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.DifferentFrom, "Assertion.SubjectConfirmationData.Recipient", "Request"), SpidErrorCode.AssertionSubjectConfirmationDataRecipientDiverso));

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.InResponseTo, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.InResponseTo), SpidErrorCode.AssertionSubjectConfDataInResponseToMancante));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.InResponseTo.Equals(request.ID), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.InResponseTo), SpidErrorCode.AssertionSubjectConfDataInResponseToDiversoIDReq));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.NotOnOrAfter"), SpidErrorCode.AssertionSubjectConfDataNotOnOrAfterNonSpec));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter == DateTime.MinValue, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.NotOnOrAfter"), SpidErrorCode.AssertionSubjectConfDataNotOnOrAfterMancante));
            DateTimeOffset notOnOrAfter = new DateTimeOffset(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter);
            BusinessValidation.ValidationCondition(() => notOnOrAfter < DateTimeOffset.UtcNow, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.NotOnOrAfterLessThenRequest, SpidErrorCode.AssertionSubjectConfDataNotOnOrAfterPreResp));

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Issuer?.Value, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.Issuer), SpidErrorCode.AssertionIssuerMancante));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Issuer.Value.Equals(identityProvider.EntityId), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Issuer), SpidErrorCode.AssertionIssuerDiversoIdP));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Issuer.Format == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, "Assertion.Issuer.Format"), SpidErrorCode.AssertionIssuerFormatNonSpec));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().Issuer.Format), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "Assertion.Issuer.Format"), SpidErrorCode.AssertionIssuerFormatMancante));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Issuer.Format.Equals(request.Issuer.Format), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Format), SpidErrorCode.AssertionIssuerFormatDiverso));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, "Assertion.Conditions"), SpidErrorCode.AssertionConditionsNonSpec));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions.GetAudienceRestriction() == null && string.IsNullOrWhiteSpace(response.GetAssertion().Conditions.NotBefore) && string.IsNullOrWhiteSpace(response.GetAssertion().Conditions.NotOnOrAfter), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "Assertion.Conditions"), SpidErrorCode.AssertionConditionsMancante));

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.NotOnOrAfter, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.NotOnOrAfter), SpidErrorCode.AssertionConditionNotOnOrAfterMancante));
            DateTimeOffset notOnOrAfterCondition = SamlDefaultSettings.ParseExact(response.GetAssertion().Conditions.NotOnOrAfter, "Assertion.Conditions.NotOnOrAfter");
            BusinessValidation.ValidationCondition(() => notOnOrAfterCondition < DateTimeOffset.UtcNow, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.NotOnOrAfterLessThenRequest, SpidErrorCode.AssertionConditionNotOnOrAfterPreResponse));


            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.NotBefore, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.NotBefore), SpidErrorCode.AssertionConditionNotBeforeMancante));
            DateTimeOffset notBefore = SamlDefaultSettings.ParseExact(response.GetAssertion().Conditions.NotBefore, "Assertion.Conditions.NotBefore");

            BusinessValidation.ValidationCondition(() => notBefore > DateTimeOffset.UtcNow, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.NotBeforeGreaterThenRequest, SpidErrorCode.AssertionConditionNotBeforeSuccResponse));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions.GetAudienceRestriction() == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "Assertion.Conditions.AudienceRestriction"), SpidErrorCode.AssertionConditionAudienceRestrictionMancante));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.GetAudienceRestriction().Audience?.First(), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.Audience), SpidErrorCode.AssertionAudienceRestrictionAudienceMancante));
            BusinessValidation.ValidationCondition(() => !(response.GetAssertion().Conditions.GetAudienceRestriction().Audience.First()?.Equals(request.Issuer.Value) ?? false), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Audience), SpidErrorCode.AssertionAudienceRestrictionAudienceNonSP));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement() == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.AuthnStatement), SpidErrorCode.AssertionAuthnStatementNonSpec));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement().AuthnInstant == DateTime.MinValue && string.IsNullOrWhiteSpace(response.GetAssertion().GetAuthnStatement().SessionIndex) && response.GetAssertion().GetAuthnStatement().AuthnContext == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, ErrorFields.AuthnStatement), SpidErrorCode.AssertionAuthStatementAuthnContextMancante));
            BusinessValidation.ValidationNotNull(response.GetAssertion().GetAuthnStatement().AuthnContext, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.AuthnContext), SpidErrorCode.AssertionAuthStatementAuthnContextNonSpec));
            BusinessValidation.ValidationNotNull(response.GetAssertion().GetAuthnStatement().AuthnContext.Items, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.AuthnContext), SpidErrorCode.AssertionAuthStatementAuthnContextNonSpec));
            BusinessValidation.ValidationNotNull(response.GetAssertion().GetAuthnStatement().AuthnContext.ItemsElementName, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, ErrorFields.AuthnContext), SpidErrorCode.AssertionAuthStatementAuthnContextNonSpec));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef() == null, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.NotSpecified, "AuthnStatement.AuthnContext.AuthnContextClassRef"), SpidErrorCode.AssertionAuthnContextAuthContextClassRefNonSpec));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef()), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "AuthnStatement.AuthnContext.AuthnContextClassRef"), SpidErrorCode.AssertionAuthnContextAuthContextClassRefMancante));
            BusinessValidation.ValidationCondition(() => !listAuthRefValid.Contains(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef()), new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.Missing, "AuthnStatement.AuthnContext.AuthnContextClassRef"), SpidErrorCode.AssertionAuthnContextAuthContextClassRefMancante));

            var responseAuthnContextClassRefLevel = int.Parse(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef().Last().ToString());
            var requestAuthnContextClassRefLevel = int.Parse(request.RequestedAuthnContext.Items[0].Last().ToString());

            BusinessValidation.ValidationCondition(() => responseAuthnContextClassRefLevel < requestAuthnContextClassRefLevel, new SpidException(ErrorLocalization.GenericMessage, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.AuthnContextClassRef), SpidErrorCode.AssertionAuthContextClassRefNonCorretto));
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
        public static LogoutRequestType GetLogoutRequest(string requestId,
            string consumerServiceURL,
            X509Certificate2 certificate,
            IdentityProvider identityProvider,
            string subjectNameId,
            string authnStatementSessionIndex,
            RequestMethod requestMethod)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(subjectNameId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(subjectNameId)));
            BusinessValidation.Argument(consumerServiceURL, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(consumerServiceURL)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));

            if (string.IsNullOrWhiteSpace(identityProvider.DateTimeFormat))
            {
                identityProvider.DateTimeFormat = SamlDefaultSettings.DateTimeFormat;
            }

            if (identityProvider.NowDelta == null)
            {
                identityProvider.NowDelta = SamlDefaultSettings.NowDelta;
            }

            if (string.IsNullOrWhiteSpace(identityProvider.GetSingleSignOutServiceUrl(requestMethod)))
            {
                throw new ArgumentNullException("The LogoutServiceUrl of the identity provider is null or empty.");
            }

            string dateTimeFormat = identityProvider.DateTimeFormat;
            string subjectNameIdRemoveText = identityProvider.SubjectNameIdRemoveText;
            string singleLogoutServiceUrl = identityProvider.GetSingleSignOutServiceUrl(requestMethod);

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
        public static LogoutResponseType GetLogoutResponse(string serializedLogoutResponse)
        {

            if (String.IsNullOrEmpty(serializedLogoutResponse))
            {
                throw new ArgumentNullException("The serializedLogoutResponse parameter can't be null or empty.");
            }

            try
            {
                return DeserializeMessage<LogoutResponseType>(serializedLogoutResponse);
            }
            catch (Exception ex)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid, ex);
            }
        }

        /// <summary>
        /// Check the validity of IdP logout response
        /// </summary>
        /// <param name="response"></param>
        /// <param name="request"></param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool ValidateLogoutResponse(LogoutResponseType response, LogoutRequestType request, string serializedResponse)
        {
            var xmlDoc = new XmlDocument() { PreserveWhitespace = true };
            xmlDoc.LoadXml(serializedResponse);

            BusinessValidation.ValidationCondition(() => !XmlHelpers.VerifySignature(xmlDoc), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.InvalidSignature, SpidErrorCode.ResponseFirmaNonValida));

            return (response.InResponseTo == request.ID);
        }

        public static string SerializeMetadata<T>(T message, bool addBillingNamespace = false) where T : class
        {
            var serializer = serializers[typeof(T)];
            var ns = new XmlSerializerNamespaces();
            ns.Add(SamlConst.md, SamlConst.Saml2pMetadata);
            ns.Add(SamlConst.ds, SamlConst.xmlnsds);
            ns.Add(SamlConst.spid, SamlConst.spidExtensions);
            if (addBillingNamespace)
                ns.Add(SamlConst.fpa, SamlConst.fpaNamespace);

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

        /// <summary>
        /// Serializes the message.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="message">The message.</param>
        /// <returns></returns>
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

        /// <summary>
        /// Deserializes the message.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static T DeserializeMessage<T>(string message) where T : class
        {
            var serializer = serializers[typeof(T)];
            using var stringReader = new StringReader(message);
            return serializer.Deserialize(stringReader) as T;
        }

        private class ErrorFields
        {
            internal static readonly string Assertion = nameof(Assertion);
            internal static readonly string AttributeStatement = nameof(AttributeStatement);
            internal static readonly string ID = nameof(ID);
            internal static readonly string IssueInstant = nameof(IssueInstant);
            internal static readonly string Subject = nameof(Subject);
            internal static readonly string NameID = nameof(NameID);
            internal static readonly string Format = nameof(Format);
            internal static readonly string SubjectConfirmation = nameof(SubjectConfirmation);
            internal static readonly string Method = nameof(Method);
            internal static readonly string SubjectConfirmationData = nameof(SubjectConfirmationData);
            internal static readonly string InResponseTo = nameof(InResponseTo);
            internal static readonly string Issuer = nameof(Issuer);
            internal static readonly string NotOnOrAfter = nameof(NotOnOrAfter);
            internal static readonly string NotBefore = nameof(NotBefore);
            internal static readonly string AudienceRestriction = nameof(AudienceRestriction);
            internal static readonly string Audience = nameof(Audience);
            internal static readonly string AuthnStatement = nameof(AuthnStatement);
            internal static readonly string AuthnContext = nameof(AuthnContext);
            internal static readonly string AuthnContextClassRef = nameof(AuthnContextClassRef);
            internal static readonly string Version = nameof(Version);
        }
    }
}
