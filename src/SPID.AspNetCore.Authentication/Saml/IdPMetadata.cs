using System.Collections.Generic;
using System.Xml.Serialization;

namespace SPID.AspNetCore.Authentication.Saml
{
    [XmlRoot(ElementName = "CanonicalizationMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class CanonicalizationMethod
    {
        [XmlAttribute(AttributeName = "Algorithm")]
        public string Algorithm { get; set; }
    }

    [XmlRoot(ElementName = "SignatureMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class SignatureMethod
    {
        [XmlAttribute(AttributeName = "Algorithm")]
        public string Algorithm { get; set; }
    }

    [XmlRoot(ElementName = "Transform", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class Transform
    {
        [XmlAttribute(AttributeName = "Algorithm")]
        public string Algorithm { get; set; }
    }

    [XmlRoot(ElementName = "Transforms", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class Transforms
    {
        [XmlElement(ElementName = "Transform", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public List<Transform> Transform { get; set; }
    }

    [XmlRoot(ElementName = "DigestMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class DigestMethod
    {
        [XmlAttribute(AttributeName = "Algorithm")]
        public string Algorithm { get; set; }
    }

    [XmlRoot(ElementName = "Reference", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class Reference
    {
        [XmlElement(ElementName = "Transforms", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public Transforms Transforms { get; set; }
        [XmlElement(ElementName = "DigestMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public DigestMethod DigestMethod { get; set; }
        [XmlElement(ElementName = "DigestValue", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public string DigestValue { get; set; }
        [XmlAttribute(AttributeName = "URI")]
        public string URI { get; set; }
    }

    [XmlRoot(ElementName = "SignedInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class SignedInfo
    {
        [XmlElement(ElementName = "CanonicalizationMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public CanonicalizationMethod CanonicalizationMethod { get; set; }
        [XmlElement(ElementName = "SignatureMethod", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public SignatureMethod SignatureMethod { get; set; }
        [XmlElement(ElementName = "Reference", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public Reference Reference { get; set; }
    }

    [XmlRoot(ElementName = "X509Data", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class X509Data
    {
        [XmlElement(ElementName = "X509Certificate", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public string X509Certificate { get; set; }
    }

    [XmlRoot(ElementName = "KeyInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class KeyInfo
    {
        [XmlElement(ElementName = "X509Data", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public X509Data X509Data { get; set; }
    }

    [XmlRoot(ElementName = "Signature", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public class Signature
    {
        [XmlElement(ElementName = "SignedInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public SignedInfo SignedInfo { get; set; }
        [XmlElement(ElementName = "SignatureValue", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public string SignatureValue { get; set; }
        [XmlElement(ElementName = "KeyInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public KeyInfo KeyInfo { get; set; }
        [XmlAttribute(AttributeName = "ds", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Ds { get; set; }
    }

    [XmlRoot(ElementName = "KeyDescriptor", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public class KeyDescriptor
    {
        [XmlElement(ElementName = "KeyInfo", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public KeyInfo KeyInfo { get; set; }
        [XmlAttribute(AttributeName = "use")]
        public string Use { get; set; }
    }

    [XmlRoot(ElementName = "SingleLogoutService", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public class SingleLogoutService
    {
        [XmlAttribute(AttributeName = "Binding")]
        public string Binding { get; set; }
        [XmlAttribute(AttributeName = "Location")]
        public string Location { get; set; }
        [XmlAttribute(AttributeName = "ResponseLocation")]
        public string ResponseLocation { get; set; }
    }

    [XmlRoot(ElementName = "SingleSignOnService", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public class SingleSignOnService
    {
        [XmlAttribute(AttributeName = "Binding")]
        public string Binding { get; set; }
        [XmlAttribute(AttributeName = "Location")]
        public string Location { get; set; }
    }

    [XmlRoot(ElementName = "IDPSSODescriptor", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public class IDPSSODescriptor
    {
        [XmlElement(ElementName = "KeyDescriptor", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
        public KeyDescriptor KeyDescriptor { get; set; }
        [XmlElement(ElementName = "SingleLogoutService", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
        public List<SingleLogoutService> SingleLogoutService { get; set; }
        [XmlElement(ElementName = "NameIDFormat", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
        public string NameIDFormat { get; set; }
        [XmlElement(ElementName = "SingleSignOnService", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
        public List<SingleSignOnService> SingleSignOnService { get; set; }
        [XmlAttribute(AttributeName = "WantAuthnRequestsSigned")]
        public string WantAuthnRequestsSigned { get; set; }
        [XmlAttribute(AttributeName = "protocolSupportEnumeration")]
        public string ProtocolSupportEnumeration { get; set; }
    }

    [XmlRoot(ElementName = "EntityDescriptor", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public class EntityDescriptor
    {
        [XmlElement(ElementName = "Signature", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public Signature Signature { get; set; }
        [XmlElement(ElementName = "IDPSSODescriptor", Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
        public IDPSSODescriptor IDPSSODescriptor { get; set; }
        [XmlAttribute(AttributeName = "ID")]
        public string ID { get; set; }
        [XmlAttribute(AttributeName = "entityID")]
        public string EntityID { get; set; }
        [XmlAttribute(AttributeName = "md", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Md { get; set; }
        [XmlAttribute(AttributeName = "ds", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Ds { get; set; }
    }

}
