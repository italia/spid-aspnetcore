using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Saml;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public sealed class ServiceProviderPublic : ServiceProvider
    {
        public string EntityId { get; set; }
        public string OrganizationDisplayName { get; set; }
        public string OrganizationName { get; set; }
        public string OrganizationURL { get; set; }
        public string IPACode { get; set; }
        public string VatNumber { get; set; }
        public string FiscalCode { get; set; }
        public string EmailAddress { get; set; }
        public string TelephoneNumber { get; set; }


        public override (string result, string contentType) Serialize()
        {
            Saml.SP.EntityDescriptorType metadata = new Saml.SP.EntityDescriptorType()
            {
                entityID = EntityId,
                ID = $"_{Id}",
                Items = new Saml.SP.SPSSODescriptorType[] {
                    new Saml.SP.SPSSODescriptorType(){
                        KeyDescriptor = new Saml.SP.KeyDescriptorType[]{
                            new Saml.SP.KeyDescriptorType(){
                                use = Saml.SP.KeyTypes.signing,
                                useSpecified = true,
                                KeyInfo = new Saml.SP.KeyInfoType
                                {
                                    ItemsElementName = new Saml.SP.ItemsChoiceType2[]{ Saml.SP.ItemsChoiceType2.X509Data },
                                    Items = new Saml.SP.X509DataType[]{
                                        new Saml.SP.X509DataType{
                                            ItemsElementName = new Saml.SP.ItemsChoiceType[]{ Saml.SP.ItemsChoiceType.X509Certificate },
                                            Items = new object[]{ Certificate.ExportPublicKey() }
                                        }
                                    }
                                }
                            },
                            new Saml.SP.KeyDescriptorType(){
                                use = Saml.SP.KeyTypes.encryption,
                                useSpecified = true,
                                KeyInfo = new Saml.SP.KeyInfoType
                                {
                                    ItemsElementName = new Saml.SP.ItemsChoiceType2[]{ Saml.SP.ItemsChoiceType2.X509Data },
                                    Items = new Saml.SP.X509DataType[]{
                                        new Saml.SP.X509DataType{
                                            ItemsElementName = new Saml.SP.ItemsChoiceType[]{ Saml.SP.ItemsChoiceType.X509Certificate },
                                            Items = new object[]{ Certificate.ExportPublicKey() }
                                        }
                                    }
                                }
                            }
                        },
                        AuthnRequestsSigned = true,
                        AuthnRequestsSignedSpecified = true,
                        WantAssertionsSigned = true,
                        WantAssertionsSignedSpecified = true,
                        protocolSupportEnumeration = new string[]{ SamlConst.Saml2pProtocol },
                        SingleLogoutService = SingleLogoutServiceLocations.Select(s => new Saml.SP.EndpointType(){
                                Binding = s.ProtocolBinding == ProtocolBinding.POST ? SamlConst.ProtocolBindingPOST : SamlConst.ProtocolBindingRedirect,
                                Location = s.Location
                            }).ToArray(),
                        NameIDFormat = new string[]{ SamlConst.NameIDPolicyFormat },
                        AssertionConsumerService = AssertionConsumerServices.Select(s => new Saml.SP.IndexedEndpointType(){
                            Binding = s.ProtocolBinding == ProtocolBinding.POST ? SamlConst.ProtocolBindingPOST : SamlConst.ProtocolBindingRedirect,
                            Location = s.Location,
                            index = s.Index,
                            isDefault = s.IsDefault,
                            isDefaultSpecified = true
                        }).ToArray(),
                        AttributeConsumingService = AttributeConsumingServices.Select(s => new Saml.SP.AttributeConsumingServiceType(){
                            index = s.Index,
                            ServiceName = new Saml.SP.localizedNameType[]{ new Saml.SP.localizedNameType(){ lang = Language, Value = s.ServiceName } },
                            ServiceDescription = new Saml.SP.localizedNameType[]{ new Saml.SP.localizedNameType(){ lang = Language, Value = s.ServiceDescription } },
                            RequestedAttribute = s.ClaimTypes.Select(c => new Saml.SP.RequestedAttributeType(){
                                NameFormat = SamlConst.RequestedAttributeNameFormat,
                                Name = c.GetSamlAttributeName()
                            }).ToArray()
                        }).ToArray(),
                    }
                },
                Organization = new Saml.SP.OrganizationType()
                {
                    OrganizationDisplayName = new Saml.SP.localizedNameType[] { new Saml.SP.localizedNameType { lang = Language, Value = OrganizationDisplayName } },
                    OrganizationName = new Saml.SP.localizedNameType[] { new Saml.SP.localizedNameType { lang = Language, Value = OrganizationName } },
                    OrganizationURL = new Saml.SP.localizedURIType[] { new Saml.SP.localizedURIType { lang = Language, Value = OrganizationURL } },
                },
                ContactPerson = new Saml.SP.ContactType[] {
                    new Saml.SP.ContactType(){
                        contactType = Saml.SP.ContactTypeType.other,
                        Extensions = new Saml.SP.ExtensionsType() { Any = GetElements() },
                        Company = OrganizationName,
                        EmailAddress = new string[]{ EmailAddress },
                        TelephoneNumber = new string[]{ TelephoneNumber }
                    }
                }
            };

            var result = SamlHandler.SignSerializedMetadata(SamlHandler.SerializeMetadata(metadata), Certificate, metadata.ID);

            return (result, "application/xml; charset=UTF-8");
        }

        private System.Xml.XmlElement[] GetElements()
        {
            var result = new List<System.Xml.XmlElement>();

            if (string.IsNullOrWhiteSpace(IPACode)
                && string.IsNullOrWhiteSpace(VatNumber)
                && string.IsNullOrWhiteSpace(FiscalCode))
            {
                throw new SpidException($"No {nameof(IPACode)} or {nameof(VatNumber)} or {nameof(FiscalCode)} were specified");
            }

            if (!string.IsNullOrWhiteSpace(IPACode))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.SP.ContactPersonAGExtensionType()
                {
                    IPACode = IPACode,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            if (!string.IsNullOrWhiteSpace(VatNumber))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.SP.ContactPersonAGExtensionType()
                {
                    VATNumber = VatNumber,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            if (!string.IsNullOrWhiteSpace(FiscalCode))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.SP.ContactPersonAGExtensionType()
                {
                    FiscalCode = FiscalCode,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.SP.ContactPersonAGExtensionType()
            {
                ItemElementName = Saml.SP.ItemChoiceType1.Public,
                Item = String.Empty,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));

            return result.ToArray();
        }
    }
}
