using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    public class ProviderManager
    {
        private readonly ProviderSettings _providerSettings;

        public ProviderManager(IOptions<ProviderSettings> providerSettings)
        {
            _providerSettings = providerSettings.Value;
        }

        public List<String> GetEditableClaims(String provider)
        {
            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(this._providerSettings, null);
            return settings?.EditableClaims ?? new List<String>();
        }

        public String GetLoginMode(String provider)
        {
            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(this._providerSettings, null);
            return settings?.LoginMode;
        }

        public Boolean HasRestrictedDomain(String provider, String domainName)
        {
            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(this._providerSettings, null);
            if (settings?.RestrictedDomains == null || settings?.RestrictedDomains.Count == 0) { return false; }
            else
            {
                return (Boolean)settings?.RestrictedDomains.Any(a => a.ToLower() == domainName.ToLower());
            }
        }

        public Boolean HasAuthorizedDomain(String provider, String domainName)
        {
            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(this._providerSettings, null);

            if (settings?.AuthorizedDomains == null || settings?.AuthorizedDomains.Count == 0) { return true; }
            else
            {
                return (Boolean)settings?.AuthorizedDomains.Any(a => a.ToLower() == domainName.ToLower());
            }
        }

        public Boolean HasEditableClaim(String provider, String claimType)
        {
            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(this._providerSettings, null);
            var items = settings?.EditableClaims;
            var claims = items != null ? String.Join(",", items) : "";

            if (claims == null || claims == "")
            {
                return false;
            }
            else
            {
                if (claims.ToLower().Contains(claimType.ToLower()))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public Boolean HasEditablePassword(String provider)
        {
            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(this._providerSettings, null);
            var mode = settings?.LoginMode;
            if (mode == "external")
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
