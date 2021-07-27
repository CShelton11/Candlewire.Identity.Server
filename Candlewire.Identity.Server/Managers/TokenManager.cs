using Candlewire.Identity.Server.Entities;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    /// <summary>
    /// Token Manager
    /// Note - Use of session manager due to tokens needed when not signed in
    /// </summary>
    public class TokenManager
    {
        private SessionManager _sessionManager;
        private UserManager<ApplicationUser> _userManager;

        public TokenManager(SessionManager sessionManager, UserManager<ApplicationUser> userManager)
        {
            _sessionManager = sessionManager;
            _userManager = userManager;
        }

        public async Task<String> GenerateVerifyEmailTokenAsync()
        {
            var persistenceKey = TokenConstants.EmailVerificationToken;
            var persistenceToken = GenerateToken();
            var persistenceData = new TokenObject() { Value = persistenceToken };
            var persistenceExpiration = DateTime.UtcNow.AddMinutes(5);

            await _sessionManager.AddAsync(persistenceKey, persistenceData, persistenceExpiration);
            return persistenceToken;
        }

        public async Task<Boolean> VerifyEmailTokenAsync(String token)
        {
            var persistenceKey = TokenConstants.EmailVerificationToken;
            var persistenceItem = await _sessionManager.GetAsync<TokenObject>(persistenceKey);

            if (persistenceItem == null)
            {
                return false;
            }
            else
            {
                if (persistenceItem.Value == token)
                {
                    await _sessionManager.RemoveAsync(persistenceKey);
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        private String GenerateToken()
        {
            Random random = new Random();
            String token = "";
            for (var i = 1; i <= 10; i++) { token += random.Next(0, 9).ToString(); }
            return token;
        }
    }

    public class TokenObject
    {
        public String Value { get; set; }
    }

    public class TokenConstants
    {
        public static String EmailVerificationToken = "EmailVerificationToken";
        public static String PhoneVerificationToken = "PhoneVerificationToken";
    }
}
