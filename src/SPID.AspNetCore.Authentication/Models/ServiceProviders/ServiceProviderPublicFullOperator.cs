using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Saml;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public class ServiceProviderPublicFullOperator : ServiceProvider
    {
        public string CodiceAttivita => "pub-op-full";
        public Saml.Aggregated.ItemChoiceType1 TipoAttivita => Saml.Aggregated.ItemChoiceType1.PublicServicesFullOperator;
        public string AggregatorEntityId { get; set; }
        public string AggregatedEntityId { get; set; }
        public string OrganizationDisplayName { get; set; }
        public string OrganizationName { get; set; }
        public string OrganizationURL { get; set; }
        public string OperatorVatNumber { get; set; }
        public string OperatorIPACode { get; set; }
        public string OperatorFiscalCode { get; set; }
        public string OperatorCompany { get; set; }
        public string OperatorEmailAddress { get; set; }
        public string OperatorTelephoneNumber { get; set; }

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
                        Extensions = new Saml.Aggregated.ExtensionsType() { Any = GetOperatorElements() },
                        Company = OperatorCompany,
                        EmailAddress = OperatorEmailAddress,
                        TelephoneNumber = OperatorTelephoneNumber
                    }
                }
            };

            var result = SamlHandler.SignSerializedMetadata(SamlHandler.SerializeMetadata(metadata), Certificate, metadata.ID);

            return (result, "application/xml; charset=UTF-8");
        }

        private System.Xml.XmlElement[] GetOperatorElements()
        {
            var result = new List<System.Xml.XmlElement>();

            if (string.IsNullOrWhiteSpace(OperatorVatNumber)
                || string.IsNullOrWhiteSpace(OperatorIPACode)
                || string.IsNullOrWhiteSpace(OperatorFiscalCode))
            {
                throw new SpidException($"No {nameof(OperatorVatNumber)}, {nameof(OperatorIPACode)} or {nameof(OperatorFiscalCode)} were specified");
            }

            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
            {
                VATNumber = OperatorVatNumber,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
            {
                IPACode = OperatorIPACode,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
            {
                FiscalCode = OperatorFiscalCode,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));
            result.Add(XmlHelpers.SerializeInternalExtensionToXmlElement(new Saml.Aggregated.ContactPersonAGExtensionType()
            {
                ItemElementName = TipoAttivita,
                Item = String.Empty,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));

            return result.ToArray();
        }
    }
}
