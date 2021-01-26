using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace SPID.AspNetCore.Authentication.Saml
{
    public static class SamlTypesExtensions
    {
        public static AssertionType GetAssertion(this ResponseType input) 
            => input.Items?.FirstOrDefault() as AssertionType;

        public static AttributeStatementType GetAttributeStatement(this AssertionType input) 
            => input.Items?.FirstOrDefault(s => s is AttributeStatementType) as AttributeStatementType;

        public static IEnumerable<AttributeType> GetAttributes(this AttributeStatementType input) 
            => input.Items?.Cast<AttributeType>();

        public static AuthnStatementType GetAuthnStatement(this AssertionType input) 
            => input.Items?.FirstOrDefault(s => s is AuthnStatementType) as AuthnStatementType;

        public static SubjectConfirmationType GetSubjectConfirmation(this SubjectType input) 
            => input.Items?.FirstOrDefault(s => s is SubjectConfirmationType) as SubjectConfirmationType;

        public static string GetAttributeValue(this AttributeType input)
            => (input.AttributeValue?.FirstOrDefault()) switch
            {
                string stringResult => stringResult,
                XmlNode[] xmlNodeResult => xmlNodeResult?.FirstOrDefault()?.Value,
                _ => null,
            };

        public static X509DataType GetX509Data(this KeyInfoType input) 
            => input.Items?.FirstOrDefault(s => s is X509DataType) as X509DataType;

        public static string GetX509Certificate(this X509DataType input) 
            => Convert.ToBase64String(input.Items?.FirstOrDefault() as byte[]);

        public static NameIDType GetNameID(this SubjectType input) 
            => input.Items?.FirstOrDefault(s => s is NameIDType) as NameIDType;

        public static AudienceRestrictionType GetAudienceRestriction(this ConditionsType input) 
            => input.Items?.FirstOrDefault(s => s is AudienceRestrictionType) as AudienceRestrictionType;

        public static string GetAuthnContextClassRef(this AuthnContextType input) 
            => input.ItemsElementName?.Contains(ItemsChoiceType5.AuthnContextClassRef) ?? false
                ? input.Items[Array.IndexOf(input.ItemsElementName, ItemsChoiceType5.AuthnContextClassRef)] as string
                : null;
    }
}
