using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Extensions
{
    public static class SigninManagerExtensions
    {
        public static async Task SignoutExternalAsync<TUser>(this SignInManager<TUser> manager, HttpContext context) where TUser : class
        {
            // Signout of all of the most common types of external authentication schemes
            // This is a catch all b/c facebook, adfs, azure, google, etc use varying types of schemes
            try { await context.SignOutAsync(IdentityConstants.ExternalScheme); } catch (Exception) { }
            try { await context.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme); } catch (Exception) { }
        }
    }
}
