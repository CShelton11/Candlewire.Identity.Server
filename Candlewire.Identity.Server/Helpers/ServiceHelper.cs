using Candlewire.Identity.Server.Settings;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Helpers
{
    public static class ServiceHelper
    {
        static IServiceProvider services = null;

        public static IServiceProvider Services
        {
            get { return services; }
            set
            {
                if (services != null)
                {
                    throw new Exception("Can't set once a value has already been set.");
                }
                services = value;
            }
        }

        public static HttpContext HttpContext_Current
        {
            get
            {
                IHttpContextAccessor httpContextAccessor = services.GetService(typeof(IHttpContextAccessor)) as IHttpContextAccessor;
                return httpContextAccessor?.HttpContext;
            }
        }

        [Obsolete]
        public static IHostingEnvironment HostingEnvironment
        {
            get
            {
                return services.GetService(typeof(IHostingEnvironment)) as IHostingEnvironment;
            }
        }

        public static ProviderSettings ProviderSettings
        {
            get
            {
                var s = services.GetService(typeof(IOptionsMonitor<ProviderSettings>)) as IOptionsMonitor<ProviderSettings>;
                ProviderSettings settings = s.CurrentValue;
                return settings;
            }
        }

    }
}
