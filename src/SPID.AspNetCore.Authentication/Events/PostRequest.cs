namespace SPID.AspNetCore.Authentication.Events;

public class PostRequest
{
    public string SAMLRequest { get; internal set; }
    public string RelayState { get; internal set; }
    public string Url { get; internal set; }
    public string SignedMessage { get; internal set; }
}
