﻿using SPID.AspNetCore.Authentication.Helpers;
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
            IdentityProvider identityProvider)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(identityProvider.SingleSignOnServiceUrl), ErrorLocalization.SingleSignOnUrlRequired);

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
                Destination = identityProvider.SingleSignOnServiceUrl,
                ForceAuthn = true,
                ForceAuthnSpecified = true,
                Issuer = new NameIDType
                {
                    Value = entityId.Trim(),
                    Format = SamlConst.IssuerFormat,
                    NameQualifier = entityId
                },
                AssertionConsumerServiceURL= assertionConsumerServiceURL,
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
                        SamlConst.SpidL + identityProvider.SecurityLevel
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

        public static string ConvertToBase64(string message) {
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

                BusinessValidation.ValidationCondition(() => response == null, ErrorLocalization.ResponseNotValid);

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
        /// <param name="metadataIdp">The metadata idp.</param>
        /// <exception cref="Exception">
        /// </exception>
        public static void ValidateAuthnResponse(this ResponseType response, AuthnRequestType request, EntityDescriptor metadataIdp, string serializedResponse)
        {
            // Verify signature
            var xmlDoc = new XmlDocument() { PreserveWhitespace = true };
            xmlDoc.LoadXml(serializedResponse);

            BusinessValidation.ValidationCondition(() => response.Status == null, ErrorLocalization.StatusNotValid);
            BusinessValidation.ValidationCondition(() => response.Status.StatusCode == null, ErrorLocalization.StatusCodeNotValid);

            if (!response.Status.StatusCode.Value.Equals(SamlConst.Success, StringComparison.InvariantCultureIgnoreCase))
            {
                if (int.TryParse(response.Status.StatusMessage?.Replace("ErrorCode nr", ""), out var errorCode))
                {
                    switch (errorCode)
                    {
                        case 8:
                            throw new Exception(ErrorLocalization._08);
                        case 9:
                            throw new Exception(ErrorLocalization._09);
                        case 11:
                            throw new Exception(ErrorLocalization._11);
                        case 12:
                            throw new Exception(ErrorLocalization._12);
                        case 13:
                            throw new Exception(ErrorLocalization._13);
                        case 14:
                            throw new Exception(ErrorLocalization._14);
                        case 15:
                            throw new Exception(ErrorLocalization._15);
                        case 16:
                            throw new Exception(ErrorLocalization._16);
                        case 17:
                            throw new Exception(ErrorLocalization._17);
                        case 18:
                            throw new Exception(ErrorLocalization._18);
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
                        case 30:
                            throw new Exception(ErrorLocalization._30);
                        default:
                            break;
                    }
                }
                throw new Exception(ErrorLocalization.StatusCodeNotValid);
            }

            BusinessValidation.ValidationCondition(() => response.Signature == null, ErrorLocalization.ResponseSignatureNotFound);
            BusinessValidation.ValidationCondition(() => response?.GetAssertion() == null, ErrorLocalization.ResponseAssertionNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion()?.Signature == null, ErrorLocalization.AssertionSignatureNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Signature.KeyInfo?.GetX509Data()?.GetBase64X509Certificate() != response.Signature.KeyInfo?.GetX509Data()?.GetBase64X509Certificate(), ErrorLocalization.AssertionSignatureDifferent);
            //var metadataXmlDoc = metadataIdp.SerializeToXmlDoc();
            BusinessValidation.ValidationCondition(() => !XmlHelpers.VerifySignature(xmlDoc, metadataIdp), ErrorLocalization.InvalidSignature);

            BusinessValidation.ValidationCondition(() => response.Version != SamlConst.Version, ErrorLocalization.VersionNotValid);
            BusinessValidation.ValidationNotNullNotWhitespace(response.ID, nameof(response.ID));

            BusinessValidation.ValidationNotNull(response.GetAssertion()?.GetAttributeStatement(), ErrorFields.Assertion);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement()?.GetAttributes()?.Count() == 0, ErrorLocalization.AttributeNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement()?.GetAttributes()?.Any(a => a.AttributeValue == null) ?? false, ErrorLocalization.AttributeNotFound);

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

            BusinessValidation.ValidationCondition(() => response.IssueInstant == default, ErrorLocalization.IssueInstantMissing);
            DateTimeOffset issueIstant = new DateTimeOffset(response.IssueInstant);
            var issueIstantRequest = DateTimeOffset.Parse(request.IssueInstant);

            BusinessValidation.ValidationCondition(() => (issueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), ErrorLocalization.IssueIstantDifferentFromRequest);

            BusinessValidation.ValidationNotNullNotWhitespace(response.InResponseTo, nameof(response.InResponseTo));

            BusinessValidation.ValidationNotNullNotWhitespace(response.Destination, nameof(response.Destination));

            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
                BusinessValidation.ValidationCondition(() => !response.Destination.Equals(request.AssertionConsumerServiceURL), string.Format(ErrorLocalization.DifferentFrom, nameof(response.Destination), nameof(request.AssertionConsumerServiceURL)));

            BusinessValidation.ValidationNotNullNotEmpty(response.Status, nameof(response.Status));

            BusinessValidation.ValidationCondition(() => response.Issuer == null, ErrorLocalization.IssuerNotSpecified);
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.Issuer?.Value), ErrorLocalization.IssuerMissing);
            BusinessValidation.ValidationCondition(() => !response.Issuer.Value.Equals(metadataIdp.EntityID, StringComparison.InvariantCultureIgnoreCase), ErrorLocalization.IssuerDifferentFromEntityId);

            BusinessValidation.ValidationCondition(() => !string.IsNullOrWhiteSpace(response.Issuer.Format) && !response.Issuer.Format.Equals(SamlConst.IssuerFormat), ErrorLocalization.IssuerFormatDifferent);

            BusinessValidation.ValidationNotNullNotEmpty(response?.GetAssertion(), ErrorFields.Assertion);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().ID == null, string.Format(ErrorLocalization.Missing, ErrorFields.ID));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().ID, ErrorFields.ID);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Version != SamlConst.Version, string.Format(ErrorLocalization.DifferentFrom, ErrorFields.Version, SamlConst.Version));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().IssueInstant == null, string.Format(ErrorLocalization.NotSpecified, ErrorFields.IssueInstant));
            DateTimeOffset assertionIssueIstant = response.GetAssertion().IssueInstant;

            BusinessValidation.ValidationCondition(() => assertionIssueIstant > issueIstantRequest.AddMinutes(10), ErrorLocalization.IssueIstantAssertionGreaterThanRequest);
            BusinessValidation.ValidationCondition(() => assertionIssueIstant < issueIstantRequest, ErrorLocalization.IssueIstantAssertionLessThanRequest);

            BusinessValidation.ValidationCondition(() => (assertionIssueIstant - issueIstantRequest).Duration() > TimeSpan.FromMinutes(10), assertionIssueIstant > issueIstantRequest ? ErrorLocalization.IssueIstantAssertionGreaterThanRequest : ErrorLocalization.IssueIstantAssertionLessThanRequest);

            BusinessValidation.ValidationNotNull(response.GetAssertion().Subject, ErrorFields.Subject);
            BusinessValidation.ValidationNotNull(response.GetAssertion().Subject?.Items, ErrorFields.Subject);
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject?.GetNameID()?.Value, ErrorFields.NameID);
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject?.GetNameID()?.Format, ErrorFields.Format);
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetNameID().Format.Equals(request.NameIDPolicy.Format), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Format));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetNameID().NameQualifier == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.NameID.NameQualifier"));
            BusinessValidation.ValidationCondition(() => String.IsNullOrWhiteSpace(response.GetAssertion().Subject.GetNameID().NameQualifier), string.Format(ErrorLocalization.Missing, "Assertion.NameID.NameQualifier"));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject.GetSubjectConfirmation(), ErrorFields.SubjectConfirmation);
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject.GetSubjectConfirmation().Method, ErrorFields.Method);
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().Method.Equals(SamlConst.Method), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Method));
            BusinessValidation.ValidationNotNullNotEmpty(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData, ErrorFields.SubjectConfirmationData);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.Recipient"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient), string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.Recipient"));
            BusinessValidation.ValidationCondition(() => !response.Destination.Equals(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient, StringComparison.OrdinalIgnoreCase), ErrorLocalization.InvalidDestination);

            if (!string.IsNullOrWhiteSpace(request.AssertionConsumerServiceURL))
                BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.Recipient.Equals(request.AssertionConsumerServiceURL), string.Format(ErrorLocalization.DifferentFrom, "Assertion.SubjectConfirmationData.Recipient", "Request"));

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.InResponseTo, ErrorFields.InResponseTo);
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.InResponseTo.Equals(request.ID), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.InResponseTo));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter == DateTime.MinValue, string.Format(ErrorLocalization.Missing, "Assertion.SubjectConfirmationData.NotOnOrAfter"));
            DateTimeOffset notOnOrAfter = new DateTimeOffset(response.GetAssertion().Subject.GetSubjectConfirmation().SubjectConfirmationData.NotOnOrAfter);
            BusinessValidation.ValidationCondition(() => notOnOrAfter < DateTimeOffset.UtcNow, ErrorLocalization.NotOnOrAfterLessThenRequest);

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Issuer?.Value, ErrorFields.Issuer);
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Issuer.Value.Equals(metadataIdp.EntityID), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Issuer));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Issuer.Format == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.Issuer.Format"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().Issuer.Format), string.Format(ErrorLocalization.Missing, "Assertion.Issuer.Format"));
            BusinessValidation.ValidationCondition(() => !response.GetAssertion().Issuer.Format.Equals(request.Issuer.Format), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Format));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions == null, string.Format(ErrorLocalization.NotSpecified, "Assertion.Conditions"));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions.GetAudienceRestriction() == null && string.IsNullOrWhiteSpace(response.GetAssertion().Conditions.NotBefore) && string.IsNullOrWhiteSpace(response.GetAssertion().Conditions.NotOnOrAfter), string.Format(ErrorLocalization.Missing, "Assertion.Conditions"));

            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.NotOnOrAfter, ErrorFields.NotOnOrAfter);
            DateTimeOffset notOnOrAfterCondition = SamlDefaultSettings.ParseExact(response.GetAssertion().Conditions.NotOnOrAfter, "Assertion.Conditions.NotOnOrAfter");
            BusinessValidation.ValidationCondition(() => notOnOrAfterCondition < DateTimeOffset.UtcNow, ErrorLocalization.NotOnOrAfterLessThenRequest);


            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.NotBefore, ErrorFields.NotBefore);
            DateTimeOffset notBefore = SamlDefaultSettings.ParseExact(response.GetAssertion().Conditions.NotBefore, "Assertion.Conditions.NotBefore");

            BusinessValidation.ValidationCondition(() => notBefore > DateTimeOffset.UtcNow, ErrorLocalization.NotBeforeGreaterThenRequest);

            BusinessValidation.ValidationCondition(() => response.GetAssertion().Conditions.GetAudienceRestriction() == null, string.Format(ErrorLocalization.Missing, "Assertion.Conditions.AudienceRestriction"));
            BusinessValidation.ValidationNotNullNotWhitespace(response.GetAssertion().Conditions.GetAudienceRestriction().Audience?.First(), ErrorFields.Audience);
            BusinessValidation.ValidationCondition(() => !(response.GetAssertion().Conditions.GetAudienceRestriction().Audience.First()?.Equals(request.Issuer.Value) ?? false), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.Audience));

            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement() == null, string.Format(ErrorLocalization.NotSpecified, ErrorFields.AuthnStatement));
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement().AuthnInstant == DateTime.MinValue && string.IsNullOrWhiteSpace(response.GetAssertion().GetAuthnStatement().SessionIndex) && response.GetAssertion().GetAuthnStatement().AuthnContext == null, string.Format(ErrorLocalization.Missing, ErrorFields.AuthnStatement));
            BusinessValidation.ValidationNotNull(response.GetAssertion().GetAuthnStatement().AuthnContext, ErrorFields.AuthnContext);
            BusinessValidation.ValidationNotNull(response.GetAssertion().GetAuthnStatement().AuthnContext.Items, ErrorFields.AuthnContext);
            BusinessValidation.ValidationNotNull(response.GetAssertion().GetAuthnStatement().AuthnContext.ItemsElementName, ErrorFields.AuthnContext);

            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef() == null, string.Format(ErrorLocalization.NotSpecified, "AuthnStatement.AuthnContext.AuthnContextClassRef"));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef()), string.Format(ErrorLocalization.Missing, "AuthnStatement.AuthnContext.AuthnContextClassRef"));
            BusinessValidation.ValidationCondition(() => !listAuthRefValid.Contains(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef()), string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.AuthnContextClassRef));

            var responseAuthnContextClassRefLevel = int.Parse(response.GetAssertion().GetAuthnStatement().AuthnContext.GetAuthnContextClassRef().Last().ToString());
            var requestAuthnContextClassRefLevel = int.Parse(request.RequestedAuthnContext.Items[0].Last().ToString());

            BusinessValidation.ValidationCondition(() => responseAuthnContextClassRefLevel < requestAuthnContextClassRefLevel, string.Format(ErrorLocalization.ParameterNotValid, ErrorFields.AuthnContextClassRef));
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
        public static LogoutRequestType GetLogoutRequest(string requestId, string consumerServiceURL, X509Certificate2 certificate,
           IdentityProvider identityProvider, string subjectNameId, string authnStatementSessionIndex)
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

            BusinessValidation.ValidationCondition(() => !XmlHelpers.VerifySignature(xmlDoc), ErrorLocalization.InvalidSignature);

            return (response.InResponseTo == request.ID);
        }

        public static string SerializeMetadata<T>(T message, bool addBillingNamespace = false) where T : class
        {
            var serializer = serializers[typeof(T)];
            var ns = new XmlSerializerNamespaces();
            ns.Add(SamlConst.md, SamlConst.Saml2pMetadata);
            ns.Add(SamlConst.ds, SamlConst.xmlnsds);
            ns.Add(SamlConst.spid, SamlConst.spidExtensions);
            if(addBillingNamespace)
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
