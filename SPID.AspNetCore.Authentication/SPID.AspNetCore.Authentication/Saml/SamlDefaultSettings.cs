using System;

namespace SPID.AspNetCore.Authentication.Saml
{
  public class SamlDefaultSettings
  {
    /// <summary>
    /// The date time format
    /// </summary>
    public const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

    /// <summary>
    /// The now delta
    /// </summary>
    public const double NowDelta = 0;

    /// <summary>
    /// The AssertionConsumerServiceIndex
    /// </summary>
    public const ushort AssertionConsumerServiceIndex = 0;

    /// <summary>
    /// The AssertionConsumerServiceIndex
    /// </summary>
    public const ushort AttributeConsumingServiceIndex = 1;
  }
}
