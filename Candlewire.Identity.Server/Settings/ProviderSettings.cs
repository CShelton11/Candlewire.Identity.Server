using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Settings
{
    public class ProviderSettings
    {
        public List<ProviderSetting> ProviderInstances { get; set; }
    }

    public class ProviderSetting
    {
        public String ProviderName { get; set; }
        public String ProviderCode { get; set; }
        public String ProviderDescription { get; set; }
        public String ProviderType { get; set; }
        public Boolean ProviderEnabled { get; set; }
        public Boolean ProviderDisplayed { get; set; }
        public String Authority { get; set; }
        public String ClientId { get; set; }
        public String ClientSecret { get; set; }
        public List<String> ClientScopes { get; set; }
        public List<String> ClientFields { get; set; }
        public String ClientResponse { get; set; }
        public String CallbackPath { get; set; }
        public String LoginMode { get; set; }
        public List<String> AuthorizedDomains { get; set; }
        public List<String> RestrictedDomains { get; set; }
        public List<String> EditableClaims { get; set; }
        public List<String> VisibleClaims { get; set; }
        public List<String> RequireClaims { get; set; }
    }
}
