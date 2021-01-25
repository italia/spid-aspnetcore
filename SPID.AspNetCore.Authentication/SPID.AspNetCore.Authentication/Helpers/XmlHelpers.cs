using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
        /// Signs an XML Document for a Saml Response
        /// </summary>
        internal static XmlElement SignXMLDoc(XmlDocument doc, X509Certificate2 certificate, string referenceUri)
        {
            if (doc == null)
            {
                throw new ArgumentNullException("The doc parameter can't be null");
            }

            if (certificate == null)
            {
                throw new ArgumentNullException("The cert2 parameter can't be null");
            }

            if (string.IsNullOrWhiteSpace(referenceUri))
            {
                throw new ArgumentNullException("The referenceUri parameter can't be null or empty");
            }

            AsymmetricAlgorithm privateKey;

            try
            {
                privateKey = certificate.PrivateKey;
            }
            catch (Exception ex)
            {
                throw new FieldAccessException("Unable to find private key in the X509Certificate", ex);
            }

            SignedXml signedXml = new SignedXml(doc)
            {
                SigningKey = privateKey 
            };

            signedXml.SignedInfo.SignatureMethod = SamlConst.SignatureMethod;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            Reference reference = new Reference
            {
                DigestMethod = SamlConst.DigestMethod
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.Uri = "#" + referenceUri;
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(certificate));
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();
            XmlElement signature = signedXml.GetXml();

            return signature;
        }

        internal static bool VerifySignature(XmlDocument signedDocument)
        {
            BusinessValidation.Argument(signedDocument, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(signedDocument)));

            SignedXml signedXml = new SignedXml(signedDocument);

            XmlNodeList nodeList = (signedDocument.GetElementsByTagName("ds:Signature")?.Count > 0) ?
                                   signedDocument.GetElementsByTagName("ds:Signature") :
                                   signedDocument.GetElementsByTagName("Signature");

            for (int i = 0; i < nodeList.Count; i++)
            {
                signedXml.LoadXml((XmlElement)nodeList[i]);
                if (!signedXml.CheckSignature()) return false;
            }
            return true;
        }

        private static readonly ConcurrentDictionary<Type, XmlSerializer> serializers = new ConcurrentDictionary<Type, XmlSerializer>();
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
    }
}
