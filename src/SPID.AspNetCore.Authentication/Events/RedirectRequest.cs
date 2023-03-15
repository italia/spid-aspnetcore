using Microsoft.Extensions.Primitives;

namespace SPID.AspNetCore.Authentication.Events;

public class RedirectRequest
{
    public string RedirectUri { get; internal set; }
    public object SAMLRequest { get; internal set; }
    public object RelayState { get; internal set; }
    public StringValues SigAlg { get; internal set; }
    public string Signature { get; internal set; }
    public string SignOnSignOutEndpoint { get; internal set; }
    public string UncompressedMessage { get; internal set; }
}