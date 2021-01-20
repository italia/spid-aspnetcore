using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SPID.AspNetCore.Authentication;
using SPID.AspNetCore.Authentication.Events;
using SPID.AspNetCore.Authentication.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SPID.AspNetCore.WebApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services
                .AddAuthentication(o => {
                    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultChallengeScheme = SpidDefaults.AuthenticationScheme;
                })
                .AddSpid(o => {
                    o.Events.OnTokenCreating = async (s) => await s.HttpContext.RequestServices.GetRequiredService<CustomSpidEvents>().TokenCreating(s);
                    o.LoadFromConfiguration(Configuration.GetSection("Spid"));
                })
                .AddCookie();
            services.AddScoped<CustomSpidEvents>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute(
                                    name: "default",
                                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        public class CustomSpidEvents : Authentication.Events.SpidEvents
        {
            public CustomSpidEvents(IServiceProvider serviceProvider)
            {

            }

            public override Task TokenCreating(SecurityTokenCreatingContext context)
            {
                return base.TokenCreating(context);
            }
        }
    }
}
