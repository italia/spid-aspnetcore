using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.IO.Compression;
using System.IO;
using System.Text;
using System;
using System.Web;
using SPID.AspNetCore.Authentication.Saml;

namespace SPID.AspNetCore.WebApp
{
    public class Program
	{
        public static void Main(string[] args)
		{


            CreateHostBuilder(args).Build().Run();
		}

		public static IHostBuilder CreateHostBuilder(string[] args) =>
				Host.CreateDefaultBuilder(args)
						.ConfigureWebHostDefaults(webBuilder =>
						{
							webBuilder.UseStartup<Startup>();
						});
	}
}
