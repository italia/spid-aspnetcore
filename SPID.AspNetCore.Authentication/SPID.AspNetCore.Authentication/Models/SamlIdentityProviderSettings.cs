using System;

namespace SPID.AspNetCore.Authentication.Models
{
  public class SamlIdentityProviderSettings
  {
    /// <summary>
    /// The single sign on service URL
    /// </summary>
    public const string SingleSignOnServiceUrl = "";

    /// <summary>
    /// The single logout service URL
    /// </summary>
    public const string SingleLogoutServiceUrl = "";

    /// <summary>
    /// The subject name identifier remove text
    /// </summary>
    public const string SubjectNameIdRemoveText = "";

    /// <summary>
    /// The date time format
    /// </summary>
    public const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

    /// <summary>
    /// The now delta
    /// </summary>
    public const double NowDelta = 0;

    /// <summary>
    /// The EntityId
    /// </summary>
    public const string EntityId = "";

    /// <summary>
    /// The AssertionConsumerServiceIndex
    /// </summary>
    public const ushort AssertionConsumerServiceIndex = 0;

    /// <summary>
    /// The AssertionConsumerServiceIndex
    /// </summary>
    public const ushort AttributeConsumingServiceIndex = 1;

    public const string Method = "Post";
  }
}
