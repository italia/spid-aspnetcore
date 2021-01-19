using System.Collections.Generic;
using System.Xml.Serialization;


namespace SPID.AspNetCore.Authentication.Models
{
    [XmlRoot(ElementName = "Issuer", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class Issuer
    {
        [XmlAttribute(AttributeName = "Format")]
        public string Format { get; set; }
        [XmlText]
        public string Text { get; set; }
    }

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

    [XmlRoot(ElementName = "StatusCode", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
    public class StatusCode
    {
        [XmlAttribute(AttributeName = "Value")]
        public string Value { get; set; }
    }

    [XmlRoot(ElementName = "Status", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
    public class Status
    {
        [XmlElement(ElementName = "StatusCode", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
        public StatusCode StatusCode { get; set; }
        [XmlElement(ElementName = "StatusMessage", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
        public string StatusMessage { get; set; }
    }

    [XmlRoot(ElementName = "NameID", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class NameID
    {
        [XmlAttribute(AttributeName = "Format")]
        public string Format { get; set; }
        [XmlAttribute(AttributeName = "NameQualifier")]
        public string NameQualifier { get; set; }
        [XmlText]
        public string Text { get; set; }
    }

    [XmlRoot(ElementName = "SubjectConfirmationData", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class SubjectConfirmationData
    {
        [XmlAttribute(AttributeName = "InResponseTo")]
        public string InResponseTo { get; set; }
        [XmlAttribute(AttributeName = "NotOnOrAfter")]
        public string NotOnOrAfter { get; set; }
        [XmlAttribute(AttributeName = "Recipient")]
        public string Recipient { get; set; }
    }

    [XmlRoot(ElementName = "SubjectConfirmation", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class SubjectConfirmation
    {
        [XmlElement(ElementName = "SubjectConfirmationData", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public SubjectConfirmationData SubjectConfirmationData { get; set; }
        [XmlAttribute(AttributeName = "Method")]
        public string Method { get; set; }
    }

    [XmlRoot(ElementName = "Subject", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class Subject
    {
        [XmlElement(ElementName = "NameID", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public NameID NameID { get; set; }
        [XmlElement(ElementName = "SubjectConfirmation", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public SubjectConfirmation SubjectConfirmation { get; set; }
    }

    [XmlRoot(ElementName = "AudienceRestriction", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class AudienceRestriction
    {
        [XmlElement(ElementName = "Audience", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public string Audience { get; set; }
    }

    [XmlRoot(ElementName = "Conditions", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class Conditions
    {
        [XmlElement(ElementName = "AudienceRestriction", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public AudienceRestriction AudienceRestriction { get; set; }
        [XmlAttribute(AttributeName = "NotBefore")]
        public string NotBefore { get; set; }
        [XmlAttribute(AttributeName = "NotOnOrAfter")]
        public string NotOnOrAfter { get; set; }
    }

    [XmlRoot(ElementName = "AuthnContext", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class AuthnContext
    {
        [XmlElement(ElementName = "AuthnContextClassRef", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public string AuthnContextClassRef { get; set; }
    }

    [XmlRoot(ElementName = "AuthnStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class AuthnStatement
    {
        [XmlElement(ElementName = "AuthnContext", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public AuthnContext AuthnContext { get; set; }
        [XmlAttribute(AttributeName = "AuthnInstant")]
        public string AuthnInstant { get; set; }
        [XmlAttribute(AttributeName = "SessionIndex")]
        public string SessionIndex { get; set; }
    }


    [XmlRoot(ElementName = "Attribute", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class Attribute
    {
        [XmlElement(ElementName = "AttributeValue", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", Type = typeof(string))]
        public string AttributeValue { get; set; }
        [XmlAttribute(AttributeName = "Name")]
        public string Name { get; set; }
        [XmlAttribute(AttributeName = "FriendlyName")]
        public string FriendlyName { get; set; }
        [XmlAttribute(AttributeName = "NameFormat")]
        public string NameFormat { get; set; }
    }

    [XmlRoot(ElementName = "AttributeStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class AttributeStatement
    {
        [XmlElement(ElementName = "Attribute", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public List<Attribute> Attribute { get; set; }
    }

    [XmlRoot(ElementName = "Assertion", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
    public class Assertion
    {
        [XmlElement(ElementName = "Issuer", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public Issuer Issuer { get; set; }
        [XmlElement(ElementName = "Signature", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public Signature Signature { get; set; }
        [XmlElement(ElementName = "Subject", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion", IsNullable = true)]
        public Subject Subject { get; set; }
        [XmlElement(ElementName = "Conditions", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public Conditions Conditions { get; set; }
        [XmlElement(ElementName = "AuthnStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public AuthnStatement AuthnStatement { get; set; }
        [XmlElement(ElementName = "AttributeStatement", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public AttributeStatement AttributeStatement { get; set; }
        [XmlAttribute(AttributeName = "ID")]
        public string ID { get; set; }
        [XmlAttribute(AttributeName = "IssueInstant")]
        public string IssueInstant { get; set; }
        [XmlAttribute(AttributeName = "Version")]
        public string Version { get; set; }
        [XmlAttribute(AttributeName = "xs", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Xs { get; set; }
        [XmlAttribute(AttributeName = "xsi", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Xsi { get; set; }
    }

    [XmlRoot(ElementName = "Response", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
    public class Response
    {
        [XmlElement(ElementName = "Issuer", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public Issuer Issuer { get; set; }
        [XmlElement(ElementName = "Signature", Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public Signature Signature { get; set; }
        [XmlElement(ElementName = "Status", Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = true)]
        public Status Status { get; set; }
        [XmlElement(ElementName = "Assertion", Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public Assertion Assertion { get; set; }
        [XmlAttribute(AttributeName = "Destination")]
        public string Destination { get; set; }
        [XmlAttribute(AttributeName = "ID")]
        public string ID { get; set; }
        [XmlAttribute(AttributeName = "InResponseTo")]
        public string InResponseTo { get; set; }
        [XmlAttribute(AttributeName = "IssueInstant")]
        public string IssueInstant { get; set; }
        [XmlAttribute(AttributeName = "Version")]
        public string Version { get; set; }
        [XmlAttribute(AttributeName = "saml", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Saml { get; set; }
        [XmlAttribute(AttributeName = "samlp", Namespace = "http://www.w3.org/2000/xmlns/")]
        public string Samlp { get; set; }
    }
}
