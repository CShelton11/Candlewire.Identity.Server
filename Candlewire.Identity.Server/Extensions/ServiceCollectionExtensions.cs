using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Candlewire.Identity.Server.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IIdentityServerBuilder AddSigningCredentials(this IIdentityServerBuilder builder, IConfigurationSection options)
        {
            var path = Directory.GetCurrentDirectory();
            var file = path + options.GetValue<String>("Path");
            var password = options.GetValue<String>("Password");

            if (File.Exists(file))
            {
                builder.AddSigningCredential(new X509Certificate2(file, password));
            }
            else
            {
                throw new System.Exception("Signing credentials file could not be found");
            }

            return builder;
        }
    }
}
