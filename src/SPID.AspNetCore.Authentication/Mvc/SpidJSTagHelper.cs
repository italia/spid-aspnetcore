using Microsoft.AspNetCore.Razor.TagHelpers;
using System.IO;
using System.Text;

namespace SPID.AspNetCore.Authentication
{
    [HtmlTargetElement("script", Attributes = "spid")]
    public class SpidJSTagHelper : TagHelper
    {
        private static string _js;
        private static readonly object _lockobj = new object();

        public override void Process(TagHelperContext context, TagHelperOutput output)
        {
            if (_js == null)
            {
                lock (_lockobj)
                {
                    if (_js == null)
                    {

                        using var resourceStream = GetType().Assembly.GetManifestResourceStream("SPID.AspNetCore.Authentication.Mvc.Resources.spid.js");
                        using var reader = new StreamReader(resourceStream, Encoding.UTF8);
                        _js = reader.ReadToEnd();
                    }
                }
            }
            output.Attributes.Remove(output.Attributes["spid"]);
            output.Content.AppendHtml(_js);
        }
    }
}
