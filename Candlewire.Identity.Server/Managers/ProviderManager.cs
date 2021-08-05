using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Enums;
using Candlewire.Identity.Server.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
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

        public LoginMode GetLoginMode(String provider)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            Enum.TryParse<LoginMode>(settings?.LoginMode, out LoginMode mode);
            return mode;
        }

        public List<String> GetVisibleClaims(String provider)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            return settings?.VisibleClaims ?? new List<String>();
        }

        public List<String> GetEditableClaims(String provider)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            return settings?.EditableClaims ?? new List<String>();
        }

        public List<String> GetRequireClaims(String provider)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            return settings?.RequireClaims ?? new List<String>();
        }

        public Boolean HasRestrictedDomain(String provider, String domainName)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            if (settings?.RestrictedDomains == null || settings?.RestrictedDomains.Count == 0) { return false; }
            else
            {
                return (Boolean)settings?.RestrictedDomains.Any(a => a.ToLower() == domainName.ToLower());
            }
        }

        public Boolean HasAuthorizedDomain(String provider, String domainName)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            if (settings?.AuthorizedDomains == null || settings?.AuthorizedDomains.Count == 0) { return true; }
            else
            {
                return (Boolean)settings?.AuthorizedDomains.Any(a => a.ToLower() == domainName.ToLower());
            }
        }

        public Boolean HasEditableClaim(String provider, String claimType)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            var items = settings?.EditableClaims;
            var claims = items != null ? items : new List<String>();

            if (claims == null || claims.Count == 0)
            {
                return false;
            }
            else
            {
                if (claims.Contains(claimType.ToLower()))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public Boolean HasRequiredClaim(String provider, String claimType)
        {
            var settings = (ProviderSetting)this._providerSettings.GetType().GetProperty(provider, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)?.GetValue(this._providerSettings, null);
            var items = settings?.RequireClaims;
            var claims = items != null ? items : new List<String>();

            if (claims == null || claims.Count == 0)
            {
                return false;
            }
            else
            {
                if (claims.Contains(claimType.ToLower()))
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
            var mode = GetLoginMode(provider);
            if (mode == LoginMode.External)
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
