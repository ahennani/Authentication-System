using Authentication_System.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System
{
    public class Startup
    {
        public IConfiguration _Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            this._Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddDbContext<AppDbContext>
                (option => option.UseSqlServer(this._Configuration.GetConnectionString("AppConnectionString")));

            services.AddScoped<AppUser>();
            services.AddScoped<ManageUsers>();

            services.AddTransient<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.RequireAuthenticatedSignIn = false;
            })
                .AddCookie("Cookies", cookieOption =>
                {
                    cookieOption.AccessDeniedPath = "/Account/Denied";
                    cookieOption.LoginPath = "/Account/Login";
                    cookieOption.LogoutPath = "/Account/Logout";

                    //cookieOption.Events = new CookieAuthenticationEvents()
                    //{
                    //    OnSigningIn = async context =>
                    //    {
                    //        var principal = context.Principal as ClaimsPrincipal;
                    //        var scheme = context.Properties.Items.Where(k => k.Key == ".AuthScheme").FirstOrDefault();
                    //        var claim = new Claim(scheme.Key, scheme.Value);
                    //        var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
                    //        var nameIdentifier = claimsIdentity.Claims.FirstOrDefault(m => m.Type == ClaimTypes.NameIdentifier)?.Value;

                    //        await Task.CompletedTask;
                    //    }
                    //};


                })
                .AddOpenIdConnect("google", options =>
                {
                    options.Authority =
                    options.CallbackPath = _Configuration.GetValue<string>("ExternalKeys:CallbackPathGoogle");
                    options.ClientId = _Configuration.GetValue<string>("ExternalKeys:ClientIdGoogle");
                    options.ClientSecret = _Configuration.GetValue<string>("ExternalKeys:ClientSecretGoogle");
                    //options.Scope.Add("openid");
                    //options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.RequireHttpsMetadata = false;
                })
                .AddOpenIdConnect("okta", options =>
                {
                    options.Authority = _Configuration.GetValue<string>("ExternalKeys:AuthorityOkta");
                    options.ClientId = _Configuration.GetValue<string>("ExternalKeys:ClientIdOkta");
                    options.ClientSecret = _Configuration.GetValue<string>("ExternalKeys:ClientSecretOkta");
                    options.CallbackPath = _Configuration.GetValue<string>("ExternalKeys:CallbackPathOkta");
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.SaveTokens = false;
                    options.SignedOutCallbackPath = "/okta-signout"; // Define it in OKTA Dashboard
                    options.SaveTokens = true; // Sent it back To Okta To Sign Out
                    options.RequireHttpsMetadata = false;
                })
                .AddFacebook("facebook", options =>
                {
                    options.AppId = _Configuration.GetValue<string>("ExternalKeys:AppId");
                    options.AppSecret = _Configuration.GetValue<string>("ExternalKeys:AppSecret");
                    options.CallbackPath = _Configuration.GetValue<string>("ExternalKeys:CallbackPathFacebook");
                })
                .AddTwitter(options =>
                {
                    options.ConsumerKey = _Configuration.GetValue<string>("ExternalKeys:ConsumerKey");
                    options.ConsumerSecret = _Configuration.GetValue<string>("ExternalKeys:ConsumerSecret");
                    options.RetrieveUserDetails = true;
                });
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
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
