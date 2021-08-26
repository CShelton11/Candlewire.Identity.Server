using Candlewire.Identity.Server.Entities;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Extensions
{
    public static class UserManagerExtensions
    {
        public static async Task<Boolean> RequiresTwoFactorAuthentication(this UserManager<ApplicationUser> manager, ApplicationUser user)
        {
            return await Task.FromResult<Boolean>(user.TwoFactorEnabled);
        }
    }
}
