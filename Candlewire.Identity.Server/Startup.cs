using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Candlewire.Identity.Server.Contexts;
using Microsoft.AspNetCore.Mvc;
using Candlewire.Identity.Server.Entities;
using Microsoft.AspNetCore.Identity;
using Candlewire.Identity.Server.Extensions;
using Microsoft.AspNetCore.DataProtection;
using IdentityServer4;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Senders;
using Candlewire.Identity.Server.Settings;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Hosting;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Migrations;
using Microsoft.Extensions.Logging;
using Serilog;
using Microsoft.IdentityModel.Tokens;
using IdentityServer4.EntityFramework.DbContexts;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;

namespace Candlewire.Identity.Server
{
    public class Startup
    {
        private IConfiguration Configuration { get; }
        private IWebHostEnvironment Environment { get; }

        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
            Log.Logger = new LoggerConfiguration().Enrich.FromLogContext().WriteTo.Console().CreateLogger();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var assemblyName = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
            var connectionString = Configuration.GetConnectionString("IdentityDatabase");
            var smsSettings = Configuration.GetSection("SmsSettings");
            var emailSettings = Configuration.GetSection("EmailSettings");
            var termSettings = Configuration.GetSection("TermSettings");
            var providerSettings = Configuration.GetSection("ProviderSettings");
            var proxySettings = Configuration.GetSection("ProxySettings");

            // Setup profile data by adding properties to application user
            services.AddIdentity<ApplicationUser, ApplicationRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

            // Setup db context for use in application
            services.AddEntityFrameworkNpgsql();

            // Setup application to use mvc
            services.AddMvc(option => option.EnableEndpointRouting = false).SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
            
            services.Configure<IISOptions>(options => {
                options.AuthenticationDisplayName = "Windows";
                options.AutomaticAuthentication = false;
            });

            // Add identity server to services and configure
            var builder = services.AddIdentityServer(options => {
                // options.Events.RaiseErrorEvents = true;
                // options.Events.RaiseInformationEvents = true;
                // options.Events.RaiseFailureEvents = true;
                // options.Events.RaiseSuccessEvents = true;
            })
            .AddConfigurationStore(config => {
                config.ConfigureDbContext = db => db.UseNpgsql(connectionString, sql => sql.MigrationsAssembly(assemblyName));
            })
            .AddOperationalStore(operations => {
                operations.ConfigureDbContext = db => db.UseNpgsql(connectionString, sql => sql.MigrationsAssembly(assemblyName));
            })
            .AddAspNetIdentity<ApplicationUser>()
            .AddSigningCredentials(Configuration.GetSection("CertificateSettings"));

            // Store data protection keys to database to enable scaling across multiple servers
            services.AddDataProtection().PersistKeysToDbContext<ProtectionDbContext>();

            // Dynamically add providers using array provided from app settings
            var providerInstances = providerSettings.GetSection("ProviderInstances").Get<List<ProviderSetting>>();
            var providerList = providerInstances.Where(a => a.ProviderEnabled && a.ProviderType?.ToLower() != "forms").ToList();
            for (var i = 0; i < providerList.Count; i++)
            {
                var providerSetting = providerList[i];
                var type = providerSetting.ProviderType;
                var authority = providerSetting.Authority;
                var name = providerSetting.ProviderName;
                var code = providerSetting.ProviderCode;
                var id = providerSetting.ClientId;
                var secret = providerSetting.ClientSecret;
                var scopes = providerSetting.ClientScopes == null ? new List<String>() : providerSetting.ClientScopes;
                var fields = providerSetting.ClientFields == null ? new List<String>() : providerSetting.ClientFields;
                var response = providerSetting.ClientResponse;
                var callback = providerSetting.CallbackPath;

                if (type.ToLower() == "openid")
                {
                    services.AddAuthentication().AddOpenIdConnect(code, name, options =>
                    {
                        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                        options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                        options.Authority = authority;
                        options.ClientId = "clientid";
                        options.ClientSecret = "clientsecret";
                        options.ResponseType = response;
                        options.CallbackPath = callback;
                        for (var j = 0; j < scopes.Count; j++) { options.Scope.Add(scopes[j]); }
                    });
                }
                else if (type.ToLower() == "google")
                {
                    services.AddAuthentication().AddGoogle(code, name, options =>
                    {
                        options.ClientId = id;
                        options.ClientSecret = secret;
                        options.CallbackPath = callback;
                        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                        for (var j = 0; j < scopes.Count; j++) { options.Scope.Add(scopes[j]); }
                    });
                }
                else if (type.ToLower() == "facebook")
                {
                    services.AddAuthentication().AddFacebook(code, name, options =>
                    {
                        options.AppId = id;
                        options.AppSecret = secret;
                        options.CallbackPath = callback;
                        for (var j = 0; j < scopes.Count; j++) { options.Scope.Add(scopes[j]); }
                        for (var j = 0; j < fields.Count; j++) { options.Fields.Add(fields[j]); }
                    });
                }
            }

            // Configure cors
            services.AddCors(options => {
                options.AddPolicy("cors", builder => { builder.AllowAnyOrigin(); });
            });

            // Add runtime compilation
            services.AddRazorPages().AddRazorRuntimeCompilation();

            // ILogger<UserManager<TUser>>
            services.AddSingleton(Serilog.Log.Logger);

            // Other dependency injection
            services.AddHttpContextAccessor();
            services.AddSingleton<IConfiguration>(Configuration);
            services.Configure<SmsSettings>(smsSettings);
            services.Configure<EmailSettings>(emailSettings);
            services.Configure<TermSettings>(termSettings);
            services.Configure<ProviderSettings>(options => providerSettings.Bind(options));
            services.Configure<ProxySettings>(proxySettings);
            services.AddTransient<IEmailSender, MessageSender>();
            services.AddTransient<ISmsSender, MessageSender>();
            services.AddTransient<SessionManager>();
            services.AddTransient<StorageManager>();
            services.AddTransient<TokenManager>();
            services.AddTransient<AccountManager>();
            services.AddTransient<ClaimManager>();
            services.AddTransient<RoleManager>();
            services.AddTransient<ProviderManager>();
            services.AddTransient<ClientManager>();
            services.AddDbContext<ApplicationDbContext>(options => options.UseNpgsql(connectionString));
            services.AddDbContext<ProtectionDbContext>(options => options.UseNpgsql(connectionString));
            services.AddDbContext<PersistenceDbContext>(options => options.UseNpgsql(connectionString));
            services.AddDbContext<ConfigurationDbContext>(options => options.UseNpgsql(connectionString));

            // This is being done solely to make these settings accessible from the service helper
            // Will be useful when making provider requirements attribute driven instead of coded in the controller
            services.AddSingleton(resolver => resolver.GetRequiredService<IOptionsMonitor<ProviderSettings>>().CurrentValue);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment environment)
        {
            Migrate(app);
            Seed(app);

            if (environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseSerilogRequestLogging();
            app.UseCors();
            app.UseSessionManager();
            app.UseRequestForwarding();
            app.UseStaticFiles();
            app.UseIdentityServer();
            app.UseMvcWithDefaultRoute();
        }

        public void Migrate(IApplicationBuilder app)
        {
            var migrator = new DatabaseMigrator();
            migrator.MigrateDatabase(app);
        }

        public void Seed(IApplicationBuilder app)
        {
            var seeder = new SeedingManager();
            seeder.Seed(Configuration.GetConnectionString("IdentityDatabase"));
        }
    }
}
