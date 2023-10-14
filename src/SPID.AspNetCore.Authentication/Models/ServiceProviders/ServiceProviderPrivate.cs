using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Helpers;
using SPID.AspNetCore.Authentication.Saml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace SPID.AspNetCore.Authentication.Models.ServiceProviders
{
    public sealed class ServiceProviderPrivate : ServiceProvider
    {
        public string EntityId { get; set; }
        public string OrganizationDisplayName { get; set; }
        public string OrganizationName { get; set; }
        public string OrganizationURL { get; set; }
        public string VatNumber { get; set; }
        public string FiscalCode { get; set; }
        public string Company { get; set; }
        public string EmailAddress { get; set; }
        public string TelephoneNumber { get; set; }
        public string BillingCompany { get; set; }
        public string BillingEmailAddress { get; set; }
        public string BillingTelephoneNumber { get; set; }
        public string CessionarioCommittenteIdPaese { get; set; }
        public string CessionarioCommittenteIdCodice { get; set; }
        public string CessionarioCommittenteCodiceFiscale { get; set; }
        public string CessionarioCommittenteDenominazione { get; set; }
        public string CessionarioCommittenteIndirizzo { get; set; }
        public string CessionarioCommittenteNumeroCivico { get; set; }
        public string CessionarioCommittenteCAP { get; set; }
        public string CessionarioCommittenteComune { get; set; }
        public string CessionarioCommittenteProvincia { get; set; }
        public string CessionarioCommittenteNazione { get; set; }

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
                            ServiceName = new Saml.SP.localizedNameType[]{ new Saml.SP.localizedNameType(){lang = Language, Value = s.ServiceName } },
                            ServiceDescription = new Saml.SP.localizedNameType[]{ new Saml.SP.localizedNameType(){lang = Language, Value = s.ServiceDescription } },
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
                        Extensions = new Saml.SP.ExtensionsType() { Any = GetAggregatorElements() },
                        Company = Company,
                        EmailAddress = new string[]{ EmailAddress },
                        TelephoneNumber = new string[]{ TelephoneNumber }
                    },
                    new Saml.SP.ContactType(){
                        contactType = Saml.SP.ContactTypeType.billing,
                        Extensions = new Saml.SP.ExtensionsType() { Any = GetBillingElements() },
                        Company = BillingCompany,
                        EmailAddress = new string[]{ BillingEmailAddress },
                        TelephoneNumber = new string[]{ BillingTelephoneNumber }
                    },
                }
            };

            var result = SamlHandler.SignSerializedMetadata(SamlHandler.SerializeMetadata(metadata, true), Certificate, metadata.ID);

            return (result, "application/xml; charset=UTF-8");
        }

        private System.Xml.XmlElement[] GetAggregatorElements()
        {
            var result = new List<System.Xml.XmlElement>();

            if (string.IsNullOrWhiteSpace(VatNumber)
                && string.IsNullOrWhiteSpace(FiscalCode))
            {
                throw new SpidException($"No {nameof(VatNumber)} or {nameof(FiscalCode)} were specified");
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
                ItemElementName = Saml.SP.ItemChoiceType1.Private,
                Item = String.Empty,
            }, Saml.SamlConst.spid, Saml.SamlConst.spidExtensions));

            return result.ToArray();
        }

        private XmlElement[] GetBillingElements()
        {
            var result = new List<System.Xml.XmlElement>();
            result.Add(XmlHelpers.SerializeExtensionToXmlElement(new Saml.SP.CessionarioCommittenteType()
            {
                DatiAnagrafici = new Saml.SP.DatiAnagraficiCessionarioType()
                {
                    Items = GetCessionarioCommittenteFields(),
                    Anagrafica = new Saml.SP.AnagraficaType()
                    {
                        Items = new string[] {
                            CessionarioCommittenteDenominazione
                        },
                        ItemsElementName = new Saml.SP.ItemsChoiceType3[] {
                            Saml.SP.ItemsChoiceType3.Denominazione
                        }
                    }
                },
                Sede = new Saml.SP.IndirizzoType()
                {
                    CAP = CessionarioCommittenteCAP,
                    Comune = CessionarioCommittenteComune,
                    Indirizzo = CessionarioCommittenteIndirizzo,
                    Nazione = CessionarioCommittenteNazione,
                    NumeroCivico = CessionarioCommittenteNumeroCivico,
                    Provincia = CessionarioCommittenteProvincia
                }
            }, Saml.SamlConst.fpa, Saml.SamlConst.fpaNamespace));
            return result.ToArray();
        }

        private object[] GetCessionarioCommittenteFields()
        {
            var result = new List<object>();

            if ((string.IsNullOrWhiteSpace(CessionarioCommittenteIdCodice)
                || string.IsNullOrWhiteSpace(CessionarioCommittenteIdPaese))
                && string.IsNullOrWhiteSpace(CessionarioCommittenteCodiceFiscale))
            {
                throw new SpidException($"No {nameof(CessionarioCommittenteIdCodice)}/{nameof(CessionarioCommittenteIdPaese)} or {nameof(CessionarioCommittenteCodiceFiscale)} were specified");
            }
            if (!string.IsNullOrWhiteSpace(CessionarioCommittenteIdCodice)
                && !string.IsNullOrWhiteSpace(CessionarioCommittenteIdPaese))
            {
                result.Add(new Saml.SP.IdFiscaleType()
                {
                    IdCodice = CessionarioCommittenteIdCodice,
                    IdPaese = CessionarioCommittenteIdPaese
                });
            }
            if (!string.IsNullOrWhiteSpace(CessionarioCommittenteCodiceFiscale))
            {
                result.Add(CessionarioCommittenteCodiceFiscale);
            }

            return result.ToArray();
        }
    }
}
