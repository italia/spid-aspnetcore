using System;

namespace SPID.AspNetCore.Authentication.Models
{
    public class IdpLogoutResponse
    {
        public string Destination { get; private set; }

        public string Id { get; private set; }

        public string InResponseTo { get; private set; }

        public DateTimeOffset IssueInstant { get; private set; }

        public string Version { get; private set; }

        public string Issuer { get; private set; }

        public string StatusCodeValue { get; private set; }

        public string StatusCodeInnerValue { get; private set; }

        public string StatusMessage { get; private set; }

        public string StatusDetail { get; private set; }

        public bool IsSuccessful
        {
            get { return StatusCodeValue == "Success"; }
        }

        public IdpLogoutResponse(string destination, string id, string inResponseTo, DateTimeOffset issueInstant, string version, string issuer,
                                 string statusCodeValue, string statusCodeInnerValue, string statusMessage, string statusDetail)
        {
            Destination = destination;
            Id = id;
            InResponseTo = inResponseTo;
            IssueInstant = issueInstant;
            Version = version;
            Issuer = issuer;
            StatusCodeValue = statusCodeValue;
            StatusCodeInnerValue = statusCodeInnerValue;
            StatusMessage = statusMessage;
            StatusDetail = statusDetail;
        }
    }
}
