using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Settings;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    public class AccountManager
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ClaimManager _claimManager;
        private readonly ILogger _logger;

        public AccountManager(UserManager<ApplicationUser> userManager, ClaimManager claimManager, ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _claimManager = claimManager;
            _logger = loggerFactory.CreateLogger<AccountManager>();
        }

        public async Task<ApplicationUser> AutoCreateUserAsync(String emailAddress, String firstName, String lastName, String nickName, DateTime? birthDate, String termDocument, String provider, String providerKey, String password = null)
        {
            var userName = Guid.NewGuid().ToString();
            var claims = _claimManager.BuildClaims(userName, emailAddress, firstName, lastName, nickName, birthDate, termDocument);
            return await AutoCreateUserAsync(userName, claims, provider, providerKey, password);
        }

        public async Task<ApplicationUser> AutoCreateUserAsync(String emailAddress, String firstName, String lastName, String nickName, DateTime? birthDate, String termDocument, String password)
        {
            var userName = Guid.NewGuid().ToString();
            var claims = _claimManager.BuildClaims(userName, emailAddress, firstName, lastName, nickName, birthDate, termDocument);
            return await AutoCreateUserAsync(userName, claims, null, null, password);
        }

        private async Task<ApplicationUser> AutoCreateUserAsync(String userName, IEnumerable<Claim> claims, String provider, String providerKey, String password)
        {
            var user = new ApplicationUser
            {
                UserName = userName,
                Email = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.Email)?.Value,
                NormalizedEmail = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.Email)?.Value.ToUpper(),
                EmailConfirmed = true,
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded) throw new Exception(result.Errors.First().Description);

            if (claims.Any())
            {
                result = await _userManager.AddClaimsAsync(user, claims);
                if (!result.Succeeded) throw new Exception(result.Errors.First().Description);
            }

            if (provider != null && providerKey != null)
            {
                result = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerKey, provider));
                if (!result.Succeeded) throw new Exception(result.Errors.First().Description);
            }

            if (password != null)
            {
                await _userManager.AddPasswordAsync(user, password);
            }

            return user;
        }

        public async Task AutoAssignRolesAsync(ApplicationUser user)
        {
            try
            {
                var currentRoles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
                //var updatedRoles = _roleSettings.Value.Data.Where(a => a.RoleDefaulted == true).Select(a => a.RoleName).ToList();

                // Next Steps
                // Add Db Context For Auto Role Assignment
                // Inject Db Context Into This Class
                // Determine If User Should Be Auto-Assigned Roles
                // Then Run Below Code



                //await _userManager.RemoveFromRolesAsync(user, currentRoles).ConfigureAwait(false);
                //await _userManager.AddToRolesAsync(user, updatedRoles).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message + ex.StackTrace?.ToString());
            }
        }
    }
}
