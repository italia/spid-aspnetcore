using System;
using System.Collections.Generic;
using System.Linq;

namespace SPID.AspNetCore.Authentication.Saml
{
    public static class SamlTypesExtensions
    {
        public static AssertionType GetAssertion(this ResponseType input)
        {
            return input.Items?.FirstOrDefault() as AssertionType;
        }

        public static AttributeStatementType GetAttributeStatement(this AssertionType input)
        {
            return input.Items?.FirstOrDefault(s => s is AttributeStatementType) as AttributeStatementType;
        }

        public static IEnumerable<AttributeType> GetAttributes(this AttributeStatementType input)
        {
            return input.Items?.Cast<AttributeType>();
        }

        public static AuthnStatementType GetAuthnStatement(this AssertionType input)
        {
            return input.Items?.FirstOrDefault(s => s is AuthnStatementType) as AuthnStatementType;
        }

        public static SubjectConfirmationType GetSubjectConfirmation(this SubjectType input)
        {
            return input.Items?.FirstOrDefault(s => s is SubjectConfirmationType) as SubjectConfirmationType;
        }

        public static string GetAttributeValue(this AttributeType input)
        {
            return input.AttributeValue?.FirstOrDefault() as string;
        }

        public static X509DataType GetX509Data(this KeyInfoType input)
        {
            return input.Items?.FirstOrDefault(s => s is X509DataType) as X509DataType;
        }

        public static string GetX509Certificate(this X509DataType input)
        {
            return Convert.ToBase64String(input.Items?.FirstOrDefault() as byte[]);
        }

        public static NameIDType GetNameID(this SubjectType input)
        {
            return input.Items?.FirstOrDefault(s => s is NameIDType) as NameIDType;
        }

        public static AudienceRestrictionType GetAudienceRestriction(this ConditionsType input)
        {
            return input.Items?.FirstOrDefault(s => s is AudienceRestrictionType) as AudienceRestrictionType;
        }

        public static string GetAuthnContextClassRef(this AuthnContextType input)
        {
            if (input.ItemsElementName?.Contains(ItemsChoiceType5.AuthnContextClassRef) ?? false)
            {
                var index = Array.IndexOf(input.ItemsElementName, ItemsChoiceType5.AuthnContextClassRef);
                return input.Items[index] as string;
            }
            return null;
        }
    }
}
