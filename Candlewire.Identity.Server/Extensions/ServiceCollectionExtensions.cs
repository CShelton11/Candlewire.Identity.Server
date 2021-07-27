using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IIdentityServerBuilder AddSigningCredentials(this IIdentityServerBuilder builder, IConfigurationSection options)
        {
            var path = options.GetValue<String>("Path");
            var password = options.GetValue<String>("Password");

            if (File.Exists(path))
            {
                builder.AddSigningCredential(new X509Certificate2(path, password));
            }
            else
            {
                throw new System.Exception("Signing credentials file could not be found");
            }

            return builder;
        }
    }
}
