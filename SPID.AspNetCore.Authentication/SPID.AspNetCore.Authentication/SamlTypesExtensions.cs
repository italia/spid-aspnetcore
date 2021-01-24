using SPID.AspNetCore.Authentication.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SPID.AspNetCore.Authentication
{
    public static class SamlTypesExtensions
    {
        public static AssertionType GetAssertion(this ResponseType input)
        {
            return input.Items[0] as AssertionType;
        }

        public static AttributeStatementType GetAttributeStatement(this AssertionType input)
        {
            return input.Items.OfType<AttributeStatementType>().FirstOrDefault();
        }

        public static IEnumerable<AttributeType> GetAttributes(this AttributeStatementType input)
        {
            return input.Items.Cast<AttributeType>();
        }

        public static AuthnStatementType GetAuthnStatement(this AssertionType input)
        {
            return input.Items.OfType<AuthnStatementType>().First();
        }

        public static SubjectConfirmationType GetSubjectConfirmation(this SubjectType input)
        {
            return input.Items.OfType<SubjectConfirmationType>().FirstOrDefault();
        }

        public static string GetAttributeValue(this AttributeType input)
        {
            return input.AttributeValue[0] as string;
        }

        public static X509DataType GetX509Data(this KeyInfoType input)
        {
            return input.Items.OfType<X509DataType>().FirstOrDefault();
        }

        public static string GetX509Certificate(this X509DataType input)
        {
            return Convert.ToBase64String(input.Items[0] as byte[]);
        }

        public static NameIDType GetNameID(this SubjectType input)
        {
            return input.Items.OfType<NameIDType>().FirstOrDefault();
        }

        public static AudienceRestrictionType GetAudienceRestriction(this ConditionsType input)
        {
            return input.Items.OfType<AudienceRestrictionType>().FirstOrDefault();
        }

        public static string GetAuthnContextClassRef(this AuthnContextType input)
        {
            var index = Array.IndexOf(input.ItemsElementName, ItemsChoiceType5.AuthnContextClassRef);
            return input.Items[index] as string;
        }
    }
}
