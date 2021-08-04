using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Settings
{
    public class ProviderSettings
    {
        public ProviderSetting Azure { get; set; }
        public ProviderSetting Adfs { get; set; }
        public ProviderSetting Google { get; set; }
        public ProviderSetting Facebook { get; set; }
        public ProviderSetting Forms { get; set; }
    }

    public class ProviderSetting
    {
        public String ClientId { get; set; }
        public String ClientSecret { get; set; }
        public String CallbackPath { get; set; }
        public String LoginMode { get; set; }
        public List<String> AuthorizedDomains { get; set; }
        public List<String> RestrictedDomains { get; set; }
        public List<String> EditableClaims { get; set; }
        public List<String> VisibleClaims { get; set; }
    }
}
