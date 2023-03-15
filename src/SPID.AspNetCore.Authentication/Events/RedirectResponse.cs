using Microsoft.Extensions.Primitives;
using System.Collections.Generic;

namespace SPID.AspNetCore.Authentication.Events;

public class RedirectResponse
{
    public string SignedMessage { get; internal set; }
    public string SAMLResponse { get; internal set; }
    public string RelayState { get; internal set; }
    public string Url { get; internal set; }
    public Dictionary<string, StringValues> Headers { get; internal set; }
    public Dictionary<string, string> Cookies { get; internal set; }
}