using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;

namespace SPID.AspNetCore.Authentication.Helpers
{
    internal static class XmlHelpers
    {
        /// <summary>
        /// Signs the XML document.
        /// </summary>
        /// <param name="doc">The document.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="referenceUri">The reference URI.</param>
        /// <param name="signatureMethod">The signature method.</param>
        /// <param name="digestMethod">The digest method.</param>
        /// <returns></returns>
        /// <exception cref="FieldAccessException"></exception>
        internal static XmlElement SignXMLDoc(XmlDocument doc,
            X509Certificate2 certificate,
            string referenceUri,
            string signatureMethod,
            string digestMethod)
        {
            BusinessValidation.ValidationNotNull(doc, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.XmlDocNull, SpidErrorCode.XmlDocNull));
            BusinessValidation.ValidationNotNull(certificate, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificateNull, SpidErrorCode.CertificateNull));
            BusinessValidation.ValidationNotNullNotWhitespace(referenceUri, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.ReferenceUriNullOrWhitespace, SpidErrorCode.ReferenceUriNullOrWhitespace));

            AsymmetricAlgorithm privateKey;

            try
            {
                privateKey = certificate.PrivateKey;
            }
            catch (Exception ex)
            {
                throw new SpidException(ErrorLocalization.PrivateKeyNotFound, ex.Message, SpidErrorCode.CertificatePrivateKeyNotFound, ex);
            }

            SignedXml signedXml = new SignedXml(doc)
            {
                SigningKey = privateKey
            };

            signedXml.SignedInfo.SignatureMethod = signatureMethod;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            Reference reference = new Reference
            {
                DigestMethod = digestMethod,
                Uri = "#" + referenceUri
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(certificate));
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            return signedXml.GetXml();
        }

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="signedDocument">The signed document.</param>
        /// <param name="xmlMetadata">The XML metadata.</param>
        /// <returns></returns>
        internal static bool VerifySignature(XmlDocument signedDocument, IdentityProvider? identityProvider = null)
        {
            BusinessValidation.Argument(signedDocument, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(signedDocument)));

            try
            {
                SignedXml signedXml = new SignedXml(signedDocument);

                if (identityProvider is not null)
                {
                    bool validated = false;
                    foreach (var certificate in identityProvider.X509SigningCertificates)
                    {
                        var publicMetadataCert = new X509Certificate2(Convert.FromBase64String(certificate));
                        XmlNodeList nodeList = (signedDocument.GetElementsByTagName("ds:Signature")?.Count > 1) ?
                                                           signedDocument.GetElementsByTagName("ds:Signature") :
                                                           (signedDocument.GetElementsByTagName("ns2:Signature")?.Count > 1) ?
                                                           signedDocument.GetElementsByTagName("ns2:Signature") :
                                                           signedDocument.GetElementsByTagName("Signature");
                        signedXml.LoadXml((XmlElement)nodeList[0]);
                        validated |= signedXml.CheckSignature(publicMetadataCert, true);
                    }
                    return validated;
                }
                else
                {
                    XmlNodeList nodeList = (signedDocument.GetElementsByTagName("ds:Signature")?.Count > 0) ?
                                           signedDocument.GetElementsByTagName("ds:Signature") :
                                           signedDocument.GetElementsByTagName("Signature");
                    signedXml.LoadXml((XmlElement)nodeList[0]);
                    return signedXml.CheckSignature();
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static readonly ConcurrentDictionary<Type, XmlSerializer> serializers = new ConcurrentDictionary<Type, XmlSerializer>();
        /// <summary>
        /// Serializes to XML document.
        /// </summary>
        /// <param name="o">The o.</param>
        /// <returns></returns>
        public static XmlDocument SerializeToXmlDoc(this object o)
        {
            XmlDocument doc = new XmlDocument() { PreserveWhitespace = true };

            using XmlWriter writer = doc.CreateNavigator().AppendChild();
            if (!serializers.ContainsKey(o.GetType()))
            {
                var serializer = new XmlSerializer(o.GetType());
                serializers.AddOrUpdate(o.GetType(), serializer, (key, value) => serializer);
            }
            serializers[o.GetType()].Serialize(writer, o);

            return doc;
        }

        public static XmlElement SerializeInternalExtensionToXmlElement(object o, string namespacePrefix, string xmlNamespace)
        {
            XmlDocument doc = SerializeExtensionToXmlElementInternal(o, namespacePrefix, xmlNamespace);

            return doc.DocumentElement.FirstChild as XmlElement;
        }

        public static XmlElement SerializeExtensionToXmlElement(object o, string namespacePrefix, string xmlNamespace)
        {
            XmlDocument doc = SerializeExtensionToXmlElementInternal(o, namespacePrefix, xmlNamespace);

            return doc.DocumentElement;
        }

        private static XmlDocument SerializeExtensionToXmlElementInternal(object o, string namespacePrefix, string xmlNamespace)
        {
            XmlDocument doc = new XmlDocument();

            using (XmlWriter writer = doc.CreateNavigator().AppendChild())
            {
                var ns = new XmlSerializerNamespaces();
                ns.Add(namespacePrefix, xmlNamespace);
                new XmlSerializer(o.GetType()).Serialize(writer, o, ns);
            }

            return doc;
        }
    }
}
