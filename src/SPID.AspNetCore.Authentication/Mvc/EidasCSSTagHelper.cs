using Microsoft.AspNetCore.Razor.TagHelpers;
using System.IO;
using System.Text;

namespace SPID.AspNetCore.Authentication
{
    [HtmlTargetElement("style", Attributes = "eidas")]
    public class EidasCSSTagHelper : TagHelper
    {
        private static string _css;
        private static readonly object _lockobj = new object();

        public override void Process(TagHelperContext context, TagHelperOutput output)
        {
            if (_css == null)
            {
                lock (_lockobj)
                {
                    if (_css == null)
                    {

                        using var resourceStream = GetType().Assembly.GetManifestResourceStream("SPID.AspNetCore.Authentication.Mvc.Resources.eidas.css");
                        using var reader = new StreamReader(resourceStream, Encoding.UTF8);
                        _css = reader.ReadToEnd();
                    }
                }
            }
            output.Content.AppendHtml(_css);
            output.Attributes.Remove(output.Attributes["eidas"]);
        }
    }
}
