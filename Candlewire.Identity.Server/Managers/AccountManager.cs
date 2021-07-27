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
        private readonly IOptions<RoleSettings> _roleSettings;
        private readonly ILogger _logger;

        public AccountManager(UserManager<ApplicationUser> userManager, IOptions<RoleSettings> roleSettings, ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _roleSettings = roleSettings;
            _logger = loggerFactory.CreateLogger<AccountManager>();
        }

        public async Task AutoAssignRolesAsync(ApplicationUser user)
        {
            try
            {
                var currentRoles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
                var updatedRoles = _roleSettings.Value.Data.Where(a => a.RoleDefaulted == true).Select(a => a.RoleName).ToList();

                await _userManager.RemoveFromRolesAsync(user, currentRoles).ConfigureAwait(false);
                await _userManager.AddToRolesAsync(user, updatedRoles).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message + ex.StackTrace.ToString());
            }
        }

        public async Task<ApplicationUser> AutoCreateUserAsync(String emailAddress, String firstName, String lastName, String nickName, DateTime birthDate, String password)
        {
            var user = new ApplicationUser
            {
                UserName = Guid.NewGuid().ToString(),
                Email = emailAddress,
                NormalizedEmail = emailAddress.ToUpper(),
                EmailConfirmed = true,
            };

            var result1 = await _userManager.CreateAsync(user);
            if (!result1.Succeeded) throw new Exception(result1.Errors.First().Description);

            var claims = CreateClaimList(emailAddress, firstName, lastName, nickName, birthDate);
            var result2 = await _userManager.AddClaimsAsync(user, claims);
            if (!result2.Succeeded) throw new Exception(result2.Errors.First().Description);

            await _userManager.AddPasswordAsync(user, password);
            return user;
        }

        public async Task<ApplicationUser> AutoCreateUserAsync(String provider, String providerUserId, String emailAddress, String firstName, String lastName, String nickName, DateTime birthDate, String password)
        {
            var claims = CreateClaimList(emailAddress, firstName, lastName, nickName, birthDate);
            return await AutoCreateUserAsync(provider, providerUserId, claims);
        }

        private List<Claim> CreateClaimList(String emailAddress, String firstName, String lastName, String nickName, DateTime birthDate)
        {
            var claims = new List<Claim>();
            var username = firstName.Substring(0, 1) + lastName.Substring(0, 1) + "-" + Guid.NewGuid().ToString().Replace("-", "");
            claims.Add(new Claim(JwtClaimTypes.Name, firstName.Trim() + " " + lastName.Trim()));
            claims.Add(new Claim(JwtClaimTypes.GivenName, firstName.Trim()));
            claims.Add(new Claim(JwtClaimTypes.FamilyName, lastName.Trim()));
            if (!String.IsNullOrEmpty(nickName)) { claims.Add(new Claim(JwtClaimTypes.NickName, nickName.Trim())); }
            claims.Add(new Claim(JwtClaimTypes.PreferredUserName, username));
            claims.Add(new Claim(JwtClaimTypes.BirthDate, birthDate.ToString("M/d/yyyy")));
            claims.Add(new Claim(JwtClaimTypes.Email, emailAddress.Trim().Replace(";", "")));
            return claims;
        }

        private async Task<ApplicationUser> AutoCreateUserAsync(String provider, String providerUserId, IEnumerable<Claim> claims)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = new List<Claim>();

            // user's display name
            var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            
            var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
            var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
            if (name == null && (first != null && last != null))
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
            }

            if (first != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.GivenName, first));
            }

            if (last != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.FamilyName, last));
            }

            var username = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.PreferredUserName)?.Value;
            if (username != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.PreferredUserName, username));
            }

            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            var upn = claims.FirstOrDefault(a => a.Type == ClaimTypes.Upn)?.Value;
            if (email == null && upn != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, upn.ToLower().Replace(";", "")));
            }
            else if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email.ToLower().Replace(";", "")));
            }

            var user = new ApplicationUser
            {
                UserName = Guid.NewGuid().ToString(),
                Email = email != null ? email.ToLower() : upn != null ? upn.ToLower() : null,
                NormalizedEmail = email != null ? email.ToUpper() : upn != null ? upn.ToUpper() : null,
                EmailConfirmed = true,
            };
            var identityResult = await _userManager.CreateAsync(user);
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, filtered);
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            if (provider != null && providerUserId != null)
            {
                identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            return user;
        }

    }
}
