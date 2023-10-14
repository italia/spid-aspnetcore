using System;

namespace SPID.AspNetCore.Authentication.Exceptions;

public class SpidException : Exception
{
    private readonly string _reason;
    private readonly SpidErrorCode _errorCode;

    public SpidErrorCode ErrorCode { get { return _errorCode; } }
    public string Reason { get { return _reason; } }

    public SpidException(string message) : base(message)
    {
        _reason = message ?? string.Empty;
        _errorCode = SpidErrorCode.GenericError;
    }

    public SpidException(string message, string reason) : base(message)
    {
        _reason = reason ?? string.Empty;
        _errorCode = SpidErrorCode.GenericError;
    }

    public SpidException(string message, string reason, SpidErrorCode errorCode) : base(message)
    {
        _reason = reason ?? string.Empty;
        _errorCode = errorCode;
    }

    public SpidException(string message, string reason, SpidErrorCode errorCode, Exception innerException) : base(message, innerException)
    {
        _reason = reason ?? string.Empty;
        _errorCode = errorCode;
    }

    public SpidException(string message, SpidErrorCode errorCode) : base(message)
    {
        _reason = message ?? string.Empty;
        _errorCode = errorCode;
    }
}

public enum SpidErrorCode
{
    ResponseNotValid = 1,
    ResponseNonFirmata = 2,
    ResponseAssertionNonFirmata = 3,
    ResponseFirmaNonValida = 4,
    ResponseIdNonSpecificato = 8,
    ResponseIdMancante = 9,
    ResponseVersionNoDue = 10,
    ResponseIssueInstantNonSpec = 11,
    ResponseIssueInstantMancante = 12,
    ResponseIssueInstantNonCorretto = 13,
    ResponseIssueInstantPreRequest = 14,
    ResponseIssueInstantSuccResponse = 15,
    ResponseInResponseToNonSpec = 16,
    ResponseInResponseToMancante = 17,
    ResponseInResponseToDiversoDaRequest = 18,
    ResponseDestinationNonSpec = 19,
    ResponseDestinationMancante = 20,
    ResponseDestinationDiversoDaAssertionConsumerServiceURL = 21,
    ResponseStatusNonSpec = 22,
    ResponseStatusMancante = 23,
    ResponseStatusCodeNonSpec = 24,
    ResponseStatusCodeMancante = 25,
    ResponseStatusCodeDiversoDaSuccess = 26,
    ResponseIssuerNonSpec = 27,
    ResponseIssuerMancante = 28,
    ResponseIssuerDiversoDaIdP = 29,
    ResponseIssuerFormatDiverso = 30,
    ResponseIssuerFormatOmesso = 31,
    ResponseAssertionMancante = 32,
    AssertionIdNonSpec = 33,
    AssertionIdMancante = 34,
    AssertionVersionNoDue = 35,
    AssertionIssueInstantNonSpec = 36,
    AssertionIssueInstantMancante = 37,
    AssertionIssueInstantNonCorretto = 38,
    AssertionIssueInstantPreRequest = 39,
    AssertionIssueInstantPostRequest = 40,
    AssertionSubjectNonSpec = 41,
    AssertionSubjectMancante = 42,
    AssertionNameIdNonSpec = 43,
    AssertionNameIdMancante = 44,
    AssertionNameIdFormatNonSpec = 45,
    AssertionNameIdFormatMancante = 46,
    AssertionNameIdFormatDiverso = 47,
    AssertionNameIdNameQualifierNonSpec = 48,
    AssertionNameIdNameQualifierMancante = 49,
    AssertionSubjectConfirmationNonSpec = 51,
    AssertionSubjectConfirmationMancante = 52,
    AssertionSubjectConfirmationMethodNonSpec = 53,
    AssertionSubjectConfirmationMethodMancante = 54,
    AssertionSubjectConfirmationMethodDiverso = 55,
    AssertionSubjectConfirmationDataMancante = 56,
    AssertionSubjectConfirmationDataRecipientNonSpec = 57,
    AssertionSubjectConfirmationDataRecipientMancante = 58,
    AssertionSubjectConfirmationDataRecipientDiverso = 59,
    AssertionSubjectConfDataInResponseToNonSpec = 60,
    AssertionSubjectConfDataInResponseToMancante = 61,
    AssertionSubjectConfDataInResponseToDiversoIDReq = 62,
    AssertionSubjectConfDataNotOnOrAfterNonSpec = 63,
    AssertionSubjectConfDataNotOnOrAfterMancante = 64,
    AssertionSubjectConfDataNotOnOrAfterNonCorretto = 65,
    AssertionSubjectConfDataNotOnOrAfterPreResp = 66,
    AssertionIssuerNonSpec = 67,
    AssertionIssuerMancante = 68,
    AssertionIssuerDiversoIdP = 69,
    AssertionIssuerFormatNonSpec = 70,
    AssertionIssuerFormatMancante = 71,
    AssertionIssuerFormatDiverso = 72,
    AssertionConditionsNonSpec = 73,
    AssertionConditionsMancante = 74,
    AssertionConditionNotBeforeNonSpec = 75,
    AssertionConditionNotBeforeMancante = 76,
    AssertionConditionNotBeforeNonCorretto = 77,
    AssertionConditionNotBeforeSuccResponse = 78,
    AssertionConditionNotOnOrAfterNonSpec = 79,
    AssertionConditionNotOnOrAfterMancante = 80,
    AssertionConditionNotOnOrAfterNonCorretto = 81,
    AssertionConditionNotOnOrAfterPreResponse = 82,
    AssertionConditionAudienceRestrictionNonSpec = 83,
    AssertionConditionAudienceRestrictionMancante = 84,
    AssertionAudienceRestrictionAudienceNonSpec = 85,
    AssertionAudienceRestrictionAudienceMancante = 86,
    AssertionAudienceRestrictionAudienceNonSP = 87,
    AssertionAuthStatementNonSpec = 88,
    AssertionAuthStatementMancante = 89,
    AssertionAuthStatementAuthnContextNonSpec = 90,
    AssertionAuthStatementAuthnContextMancante = 91,
    AssertionAuthnContextAuthContextClassRefNonSpec = 92,
    AssertionAuthnContextAuthContextClassRefMancante = 93,
    AssertionAuthContextClassRefSpidL1 = 94,
    AssertionAuthContextClassRefSpidL2 = 95,
    AssertionAuthContextClassRefSpidL3 = 96,
    AssertionAuthContextClassRefNonCorretto = 97,
    AssertionAttributeStatementNoAttribute = 98,
    AssertionAttributeStatementNoSpecAttribute = 99,
    AssertionFirmaDiversa = 100,
    AssertionSetAttribDiversiDaReq = 103,
    Anomalia19 = 104,
    Anomalia20 = 105,
    Anomalia21 = 106,
    Anomalia22 = 107,
    Anomalia23 = 108,
    AttribNoNameFormat = 109,
    ResponseIssueInstantNoMs = 110,
    Anomalia25 = 111,
    //utilizzato il 1000 per non "occupare" valori che potrebbero essere relativi a nuovi test AgID
    ArgumentNull = 1000,
    SSOUrlRequired = 1001,
    ResponseMancante = 1002,
    AttributiRichiestiMancanti = 1003,
    AssertionAuthnStatementNonSpec = 1004,
    SpidPropertiesNotFound = 1005,
    XmlDocNull = 1006,
    CertificateNull = 1007,
    ReferenceUriNullOrWhitespace = 1008,
    CertificatePathNullOrEmpty = 1009,
    CertificatePasswordNullOrEmpty = 1010,
    CertificatePrivateKeyNotFound = 1011,
    SAMLInvalid = 1111,
    InvalidClaimType = 1112,
    CertificateRawStringNullOrEmpty = 1012,
    CertificateFindValueNullOrEmpty = 1013,
    IsPassiveTrue = 1115,
    AttributeConsumerServiceIndexNonCorretto = 1118,
    Anomalia30 = 1130,
    GenericError = 9999
}
