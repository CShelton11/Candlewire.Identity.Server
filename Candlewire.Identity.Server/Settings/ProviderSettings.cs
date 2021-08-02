using System;
using System.Collections.Generic;
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
        public ProviderSettings Twitter { get; set; }
        public ProviderSetting Forms { get; set; }

        public class ProviderSetting
        {
            public String LoginMode { get; set; }
            public List<String> AuthorizedDomains { get; set; }
            public List<String> RestrictedDomains { get; set; }
            public List<ProviderClaim> ProviderClaims { get; set; }
        }

        public class ProviderClaim
        {
            public String ClaimName { get; set; }
            public String ClaimType { get; set; }
            public String Visible { get; set; }
            public String Editable { get; set; }
            public String Required { get; set; }
        }
    }
}
