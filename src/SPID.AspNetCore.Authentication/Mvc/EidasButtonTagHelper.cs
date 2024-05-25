using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Razor.TagHelpers;
using System;
using System.Collections.Generic;
using System.IO;

namespace SPID.AspNetCore.Authentication
{
    public class EidasButtonTagHelper : TagHelper
    {
        private static readonly Dictionary<EidasButtonType, string> _serializedCircleImagesSVG = new Dictionary<EidasButtonType, string>();
        private static readonly Dictionary<EidasButtonType, string> _serializedCircleImagesPNG = new Dictionary<EidasButtonType, string>();
        private static readonly object _lockobj = new object();

        private static readonly Dictionary<EidasButtonSize, (string ShortClassName, string LongClassName)> _classNames = new()
        {
            { EidasButtonSize.Small, ("s", "small") },
            { EidasButtonSize.Medium, ("m", "medium") },
            { EidasButtonSize.Large, ("l", "large") },
            { EidasButtonSize.ExtraLarge, ("xl", "xlarge") }
        };

        readonly IUrlHelper _urlHelper;

        public EidasButtonTagHelper(IUrlHelper urlHelper)
        {
            _urlHelper = urlHelper;
        }

        public EidasButtonSize Size { get; set; } = EidasButtonSize.Medium;

        public EidasButtonType CircleImageType { get; set; } = EidasButtonType.db;

        public string CircleImagePath { get; set; }

        public string ChallengeUrl { get; set; }

        public override void Process(TagHelperContext context, TagHelperOutput output)
        {
            output.TagName = "div";
            output.Content.AppendHtml(CreateHeader());
        }

        private TagBuilder CreateHeader()
        {
            var spanIcon = new TagBuilder("span");
            spanIcon.AddCssClass("italia-it-button-icon");

            var imgIcon = new TagBuilder("img");
            imgIcon.Attributes.Add("src", String.IsNullOrWhiteSpace(CircleImagePath) ? GetSerializedCircleImageSVG() : _urlHelper.Content(CircleImagePath));
            imgIcon.Attributes.Add("alt", string.Empty);
            imgIcon.Attributes.Add("onerror", $"this.src='{(String.IsNullOrWhiteSpace(CircleImagePath) ? GetSerializedCircleImagePNG() : _urlHelper.Content(CircleImagePath))}'; this.onerror=null;");
            spanIcon.AddCssClass("italia-it-button-icon");
            spanIcon.InnerHtml.AppendHtml(imgIcon);

            var spanText = new TagBuilder("span");
            spanText.AddCssClass("italia-it-button-text");
            spanText.InnerHtml.Append("Login with eIDAS");

            var a = new TagBuilder("a");
            a.Attributes.Add("href", $"{ChallengeUrl}{(ChallengeUrl.Contains("?") ? "&" : "?")}idpname=Eidas");
            a.Attributes.Add("class", $"italia-it-button italia-it-button-size-{_classNames[Size].ShortClassName} button-eidas");
            a.Attributes.Add("eidas-idp-button", $"#eidas-idp-button-{_classNames[Size].LongClassName}-get");
            a.Attributes.Add("aria-haspopup", "false");
            a.Attributes.Add("aria-expanded", "false");

            a.InnerHtml.AppendHtml(spanIcon).AppendHtml(spanText);
            return a;
        }

        private string GetSerializedCircleImageSVG()
        {
            if (!_serializedCircleImagesSVG.ContainsKey(CircleImageType))
            {
                lock (_lockobj)
                {
                    if (!_serializedCircleImagesSVG.ContainsKey(CircleImageType))
                    {
                        using var resourceStream = GetType().Assembly.GetManifestResourceStream($"SPID.AspNetCore.Authentication.Mvc.Resources.ficep-it-eidas-{CircleImageType}.svg");
                        using var writer = new MemoryStream();
                        resourceStream.CopyTo(writer);
                        writer.Seek(0, SeekOrigin.Begin);
                        _serializedCircleImagesSVG.Add(CircleImageType, $"data:image/svg+xml;base64,{Convert.ToBase64String(writer.ToArray())}");
                    }
                }
            }
            return _serializedCircleImagesSVG[CircleImageType];
        }

        private string GetSerializedCircleImagePNG()
        {
            if (!_serializedCircleImagesPNG.ContainsKey(CircleImageType))
            {
                lock (_lockobj)
                {
                    if (!_serializedCircleImagesPNG.ContainsKey(CircleImageType))
                    {
                        using var resourceStream = GetType().Assembly.GetManifestResourceStream($"SPID.AspNetCore.Authentication.Mvc.Resources.ficep-it-eidas-{CircleImageType}.png");
                        using var writer = new MemoryStream();
                        resourceStream.CopyTo(writer);
                        writer.Seek(0, SeekOrigin.Begin);
                        _serializedCircleImagesPNG.Add(CircleImageType, $"data:image/png;base64,{Convert.ToBase64String(writer.ToArray())}");
                    }
                }
            }
            return _serializedCircleImagesPNG[CircleImageType];
        }

    }

    public enum EidasButtonSize
    {
        Small,
        Medium,
        Large,
        ExtraLarge
    }

    public enum EidasButtonType
    {
        db,
        lb,
        ybw,
        ywb
    }
}
