using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Saml;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public abstract class ServiceProviderPublicAggregator : ServiceProvider
    {
        public abstract string CodiceAttivita { get; }
        public abstract Saml.Aggregated.ItemChoiceType1 TipoAttivita { get; }
        public string AggregatorEntityId { get; set; }
        public string AggregatedEntityId { get; set; }
        public string OrganizationDisplayName { get; set; }
        public string OrganizationName { get; set; }
        public string OrganizationURL { get; set; }
        public string AggregatorIPACode { get; set; }
        public string AggregatorVatNumber { get; set; }
        public string AggregatorFiscalCode { get; set; }
        public string AggregatorCompany { get; set; }
        public string AggregatorEmailAddress { get; set; }
        public string AggregatorTelephoneNumber { get; set; }
        public string AggregatedIPACode { get; set; }
        public string AggregatedVatNumber { get; set; }
        public string AggregatedFiscalCode { get; set; }

        public override (string result, string contentType) Serialize()
        {
            Saml.Aggregated.EntityDescriptorType metadata = new Saml.Aggregated.EntityDescriptorType()
            {
                entityID = $"https://{AggregatorEntityId}/{CodiceAttivita}/{AggregatedEntityId}",
                ID = $"_{Id}",
                Items = new Saml.Aggregated.SPSSODescriptorType[] {
                    new Saml.Aggregated.SPSSODescriptorType(){
                        KeyDescriptor = new Saml.Aggregated.KeyDescriptorType[]{
                            new Saml.Aggregated.KeyDescriptorType(){
                                use = Saml.Aggregated.KeyTypes.signing,
                                useSpecified = true,
                                KeyInfo = new Saml.Aggregated.KeyInfoType
                                {
                                    ItemsElementName = new Saml.Aggregated.ItemsChoiceType2[]{ Saml.Aggregated.ItemsChoiceType2.X509Data },
                                    Items = new Saml.Aggregated.X509DataType[]{
                                        new Saml.Aggregated.X509DataType{
                                            ItemsElementName = new Saml.Aggregated.ItemsChoiceType[]{ Saml.Aggregated.ItemsChoiceType.X509Certificate },
                                            Items = new object[]{ Certificate.ExportPublicKey() }
                                        }
                                    }
                                }
                            },
                            new Saml.Aggregated.KeyDescriptorType(){
                                use = Saml.Aggregated.KeyTypes.encryption,
                                useSpecified = true,
                                KeyInfo = new Saml.Aggregated.KeyInfoType
                                {
                                    ItemsElementName = new Saml.Aggregated.ItemsChoiceType2[]{ Saml.Aggregated.ItemsChoiceType2.X509Data },
                                    Items = new Saml.Aggregated.X509DataType[]{
                                        new Saml.Aggregated.X509DataType{
                                            ItemsElementName = new Saml.Aggregated.ItemsChoiceType[]{ Saml.Aggregated.ItemsChoiceType.X509Certificate },
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
                        SingleLogoutService = SingleLogoutServiceLocations.Select(s => new Saml.Aggregated.EndpointType(){
                                Binding = s.ProtocolBinding == ProtocolBinding.POST ? SamlConst.ProtocolBindingPOST : SamlConst.ProtocolBindingRedirect,
                                Location = s.Location
                            }).ToArray(),
                        NameIDFormat = new string[]{ SamlConst.NameIDPolicyFormat },
                        AssertionConsumerService = AssertionConsumerServices.Select(s => new Saml.Aggregated.IndexedEndpointType(){
                            Binding = s.ProtocolBinding == ProtocolBinding.POST ? SamlConst.ProtocolBindingPOST : SamlConst.ProtocolBindingRedirect,
                            Location = s.Location,
                            index = s.Index,
                            isDefault = s.IsDefault,
                            isDefaultSpecified = true
                        }).ToArray(),
                        AttributeConsumingService = AttributeConsumingServices.Select(s => new Saml.Aggregated.AttributeConsumingServiceType(){
                            index = s.Index,
                            ServiceName = new Saml.Aggregated.localizedNameType[]{ new Saml.Aggregated.localizedNameType(){lang = Language, Value = s.ServiceName } },
                            ServiceDescription = new Saml.Aggregated.localizedNameType[]{ new Saml.Aggregated.localizedNameType(){lang = Language, Value = s.ServiceDescription } },
                            RequestedAttribute = s.ClaimTypes.Select(c => new Saml.Aggregated.RequestedAttributeType(){
                                NameFormat = SamlConst.RequestedAttributeNameFormat,
                                Name = c.GetSamlAttributeName()
                            }).ToArray()
                        }).ToArray(),
                    }
                },
                Organization = new Saml.Aggregated.OrganizationType()
                {
                    OrganizationDisplayName = new Saml.Aggregated.localizedNameType[] { new Saml.Aggregated.localizedNameType { lang = Language, Value = OrganizationDisplayName } },
                    OrganizationName = new Saml.Aggregated.localizedNameType[] { new Saml.Aggregated.localizedNameType { lang = Language, Value = OrganizationName } },
                    OrganizationURL = new Saml.Aggregated.localizedURIType[] { new Saml.Aggregated.localizedURIType { lang = Language, Value = OrganizationURL } },
                },
                ContactPerson = new Saml.Aggregated.ContactType[] {
                    new Saml.Aggregated.ContactType(){
                        contactType = Saml.Aggregated.ContactTypeType.other,
                        entityType = Saml.Aggregated.EntityTypeType.spidaggregator,
                        Extensions = new Saml.Aggregated.ExtensionsType() { Any = GetAggregatorElements() },
                        Company = AggregatorCompany,
                        EmailAddress = AggregatorEmailAddress,
                        TelephoneNumber = AggregatorTelephoneNumber
                    },
                    new Saml.Aggregated.ContactType(){
                        contactType = Saml.Aggregated.ContactTypeType.other,
                        entityType = Saml.Aggregated.EntityTypeType.spidaggregated,
                        Extensions = new Saml.Aggregated.ExtensionsType() { Any = GetAggregatedElements() },
                        Company = OrganizationName
                    }
                }
            };

            var result = SamlHandler.SignSerializedMetadata(SamlHandler.SerializeMetadata(metadata), Certificate, metadata.ID);

            return (result, "application/xml; charset=UTF-8");
        }

        private System.Xml.XmlElement[] GetAggregatorElements()
        {
            var result = new List<System.Xml.XmlElement>();

            if (string.IsNullOrWhiteSpace(AggregatorIPACode)
                && string.IsNullOrWhiteSpace(AggregatorVatNumber)
                && string.IsNullOrWhiteSpace(AggregatorFiscalCode))
            {
                throw new SpidException($"No {nameof(AggregatorIPACode)} or {nameof(AggregatorVatNumber)} or {nameof(AggregatorFiscalCode)} were specified");
            }

            if (!string.IsNullOrWhiteSpace(AggregatorIPACode))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
                {
                    IPACode = AggregatorIPACode,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            if (!string.IsNullOrWhiteSpace(AggregatorVatNumber))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
                {
                    VATNumber = AggregatorVatNumber,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            if (!string.IsNullOrWhiteSpace(AggregatorFiscalCode))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
                {
                    FiscalCode = AggregatorFiscalCode,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
            {
                ItemElementName = TipoAttivita,
                Item = String.Empty,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));

            return result.ToArray();
        }

        private System.Xml.XmlElement[] GetAggregatedElements()
        {
            var result = new List<System.Xml.XmlElement>();

            if (string.IsNullOrWhiteSpace(AggregatedIPACode))
            {
                throw new SpidException($"No {nameof(AggregatedIPACode)} was specified");
            }

            if (!string.IsNullOrWhiteSpace(AggregatedIPACode))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
                {
                    IPACode = AggregatedIPACode,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            if (!string.IsNullOrWhiteSpace(AggregatedVatNumber))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
                {
                    VATNumber = AggregatedVatNumber,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            if (!string.IsNullOrWhiteSpace(AggregatedFiscalCode))
            {
                result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
                {
                    FiscalCode = AggregatedFiscalCode,
                }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            }
            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
            {
                ItemElementName = Saml.Aggregated.ItemChoiceType1.Public,
                Item = String.Empty,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));

            return result.ToArray();
        }
    }
}
