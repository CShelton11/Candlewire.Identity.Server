// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;
using Candlewire.Identity.Server.Attributes;
using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Models.AccountViewModels;
using Candlewire.Identity.Server.Options;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using Newtonsoft.Json;
using Candlewire.Identity.Server.Enums;
using IdentityServer4;
using System.Security.Claims;
using System.Security.Principal;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Extensions;
using Candlewire.Identity.Server.Settings;
using Microsoft.Extensions.Options;
using System.Globalization;

namespace Candlewire.Identity.ServerControllers
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly ProviderManager _providerManager;
        private readonly TokenManager _tokenManager;
        private readonly SessionManager _sessionManager;
        private readonly AccountManager _accountManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ClaimManager _claimManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ILogger _logger;

        public AccountController(
            ProviderManager providerManager,
            TokenManager tokenManager,
            SessionManager sessionManager,
            AccountManager accountManager,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ClaimManager claimManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILoggerFactory loggerFactory)
        {
            _providerManager = providerManager;
            _tokenManager = tokenManager;
            _sessionManager = sessionManager;
            _accountManager = accountManager;
            _userManager = userManager;
            _signInManager = signInManager;
            _claimManager = claimManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        [HttpPost]
        public IActionResult Create()
        {
            return RedirectToAction("Signup", "Register");
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            await _signInManager.SignOutAsync();                        // Ensures current internal login is destroyed
            await _signInManager.SignoutExternalAsync(HttpContext);     // Ensures previous external signin is destroyed
            await _sessionManager.ClearAsync();                         // Ensures previous session data is destroyed 

            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            var model = await BuildLoginViewModelAsync(returnUrl, context);

            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            ModelState.Clear();

            var returnUrl = model.ReturnUrl;

            // Email model validation
            if (String.IsNullOrEmpty(model.Email))
            {
                ModelState.AddModelError("", "Email Address is required");
                model.StepNumber = "1";
                model.Password = "";
                return View(model);
            }
            else if (model.Email?.IsValidEmail() == false)
            {
                ModelState.AddModelError("", "Email Address is not valid");
                model.StepNumber = "1";
                model.Password = "";
                return View(model);
            }

            // Move to next step and return
            if (model.StepNumber == "1" && String.IsNullOrEmpty(model.Email) == false && model.Email?.IsValidEmail() == true)
            {
                model.StepNumber = "2";
                model.Password = "";
                return View(model);
            }

            // Password model validation
            if (model.StepNumber == "2")
            {
                if (String.IsNullOrEmpty(model.Password) == true)
                {
                    ModelState.AddModelError("", "Password is required");
                    model.StepNumber = "2";
                    model.Password = "";
                    return View(model);
                }
            }

            // Check if domain is assigned to external only provider
            // If so and enabled, the use external login provider
            var settings1 = _providerManager.GetSettingsByAuthorizedDomain(model.Email.GetDomainName());
            if (settings1 != null)
            {
                var provider = settings1.ProviderCode;
                var enabled = settings1.ProviderEnabled;
                var mode = settings1.LoginMode;

                if (mode.ToLower() == "external" && enabled == true)
                {
                    // Need to determine how to provide login hint so that email address is automatically sent over
                    return RedirectToAction("ExternalLogin", new { provider = provider, returnUrl = returnUrl });
                }
            }
            
            // If forms authentication enabled, validate credentials
            var settings2 = _providerManager.GetSettingsByProviderCode("forms");
            if (settings2 != null)
            {
                var enabled = settings2.ProviderEnabled;

                if (enabled == true)
                {
                    var matches = await _userManager.GetUsersForClaimAsync(new Claim(JwtClaimTypes.Email, model.Email));
                    if (matches.Count != 1)
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                        model.Password = "";
                        return View(model);
                    }

                    var user = matches.FirstOrDefault();
                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberLogin, lockoutOnFailure: false);
                    if (result.Succeeded)
                    {
                        _logger.LogInformation(1, "User logged in.");
                        return RedirectToLocal(returnUrl);
                    }

                    if (result.IsLockedOut)
                    {
                        _logger.LogWarning(2, "User account locked out.");
                        return View("Lockout");
                    }

                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToAction(nameof(Send), new { ReturnUrl = returnUrl, RememberMe = model.RememberLogin });
                    }

                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    model.StepNumber = "2";
                    model.Password = "";
                    return View(model);
                }
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            model.StepNumber = "1";
            model.Password = "";
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            var authenticated = User?.Identity.IsAuthenticated ?? false;
            var vm = await BuildLogoutViewModelAsync(logoutId, authenticated);

            if (vm.ShowLogoutPrompt == false)
            {
                await _sessionManager.ClearAsync();
                await _signInManager.SignOutAsync();
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
                return RedirectToAction("Login");
            }
            else
            {
                return View(vm);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel model)
        {
            if (User?.Identity.IsAuthenticated == true)
            {
                await _sessionManager.ClearAsync();  // Destroys session data
                await _signInManager.SignOutAsync();
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            if (model.TriggerExternalSignout)
            {
                string url = Url.Action("Logout", new { logoutId = model.LogoutId });
                return SignOut(new AuthenticationProperties { RedirectUri = url }, model.ExternalAuthenticationScheme);
            }

            return View("Logout", model);
        }

        [HttpPost]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider = null, string returnUrl = null)
        {
            // Need to add default return url if none is provided
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl, AuthorizationRequest context)
        {
            var model = new LoginViewModel
            {
                StepNumber = "1",
                ReturnUrl = returnUrl, 
                Email = context?.LoginHint,
                Password = ""
            };
            return await Task.FromResult<LoginViewModel>(model);
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId, Boolean authenticated)
        {
            if (authenticated == true)
            {
                var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt, Authenticated = authenticated };

                if (User?.Identity.IsAuthenticated != true)
                {
                    // if the user is not authenticated, then just show logged out page
                    vm.ShowLogoutPrompt = false;
                    return vm;
                }

                var context = await _interaction.GetLogoutContextAsync(logoutId);
                if (context?.ShowSignoutPrompt == false)
                {
                    // it's safe to automatically sign-out
                    vm.ShowLogoutPrompt = false;
                    return vm;
                }

                // show the logout prompt. this prevents attacks where the user
                // is automatically signed out by another malicious web page.
                return vm;
            }
            else
            {
                // get context information (client name, post logout redirect URI and iframe for federated signout)
                var logout = await _interaction.GetLogoutContextAsync(logoutId);

                var vm = new LogoutViewModel
                {
                    AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                    PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                    ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                    SignOutIframeUrl = logout?.SignOutIFrameUrl,
                    LogoutId = logoutId,
                    Authenticated = authenticated
                };

                if (User?.Identity.IsAuthenticated == true)
                {
                    var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                    if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                    {
                        var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                        if (providerSupportsSignout)
                        {
                            if (vm.LogoutId == null)
                            {
                                // if there's no current logout context, we need to create one
                                // this captures necessary info from the current logged in user
                                // before we signout and redirect away to the external IdP for signout
                                vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                            }

                            vm.ExternalAuthenticationScheme = idp;
                        }
                    }
                }

                return vm;
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> Send(string returnUrl = null, bool rememberMe = false)
        {
            var model = new SendViewModel();
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            
            if (user == null)
            {
                return View("Error");
            }

            if (user.EmailConfirmed == true)
            {
                model.AvailableProviders.Add("Email");
            }

            if (user.PhoneNumberConfirmed == true)
            {
                model.AvailableProviders.Add("Phone");
            }

            if (model.AvailableProviders.Count == 1)
            {
                var provider = model.AvailableProviders.FirstOrDefault();
                var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);

                if (provider == "Email")
                {
                    var email = await _userManager.GetEmailAsync(user);
                    var subject = "Candlewire Login Code";
                    var message = "Your Candlewire security code is: " + code;
                    await _emailSender.SendEmailAsync(email, subject, message);
                }
                else
                {
                    var phone = await _userManager.GetPhoneNumberAsync(user);
                    var message = "Your Candlewire security code is: " + code;
                    await _smsSender.SendSmsAsync(phone, message);
                }

                return RedirectToAction(nameof(Verify), new { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
            }
            else
            {
                return View(model);
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> Send(SendViewModel model)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null || ModelState.IsValid == false)
            {
                return View("Error");
            }

            var provider = model.SelectedProvider;
            if (provider == "Email")
            {
                var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);
                var email = await _userManager.GetEmailAsync(user);
                var subject = "Candlewire Login Code";
                var message = $"Your Candlewire security code is: " + code;
                await _emailSender.SendEmailAsync(email, subject, message);
            }
            else
            {
                var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);
                var phone = await _userManager.GetPhoneNumberAsync(user);
                var message = "Your Candlewire security code is: " + code;
                await _smsSender.SendSmsAsync(phone, message);
            }

            return RedirectToAction(nameof(Verify), new { Provider = provider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Verify(string provider, bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerifyViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify(VerifyViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);
            if (result.Succeeded)
            {
                var user = await _signInManager.GetTwoFactorAuthenticationUserAsync().ConfigureAwait(false);
                return RedirectToLocal(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "The provided code is not valid");
                return View(model);
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Reset(string userId, string code = null)
        {
            var model = new ResetViewModel() { Completed = false, Code = code };
            return code == null ? View("Error") : View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Reset(ResetViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                user.AccessFailedCount = 0;
                user.LockoutEnd = null;
                await _userManager.UpdateAsync(user);
            }

            // Always return completed to hide invalid email address or invalid code
            model.Completed = true;
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Forgot()
        {
            var model = new ForgotViewModel() { Completed = false };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Forgot(ForgotViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null) {
                    model.Completed = true;
                    return View(model);
                }

                var provider = await GetProvider(user);
                var mode = _providerManager.GetLoginMode(provider);
                if (mode == LoginMode.External)
                {
                    ModelState.AddModelError("", "Password reset is not available for this account");
                    return View(model);
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("Reset", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
                model.Completed = true;
                return View(model);
            }

            return View(model);
        }

        private async Task<AuthenticateResult> AuthenticateAsync(String scheme)
        {
            try
            {
                var result = await HttpContext.AuthenticateAsync(scheme);
                if (result.Succeeded == true) { _logger.LogInformation("AuthenticateAsync successful for scheme " + scheme); }
                else { _logger.LogInformation("AuthenticateAsync unsuccessful for scheme " + scheme); }
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AuthenticateAsync unsuccessful for scheme " + scheme);
                return null;
            }
        }

        /// <summary>
        /// Get external login identity from the temporary cookie
        /// </summary>
        /// <returns></returns>
        private async Task<AuthenticateResult> ExternalLoginResult()
        {
            AuthenticateResult result = null;
            AuthenticateResult resultA = await AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            AuthenticateResult resultB = await AuthenticateAsync(IdentityConstants.ExternalScheme);

            if (resultA?.Succeeded == true) { result = resultA; }
            else if (resultB?.Succeeded == true) { result = resultB; }
            else
            {
                _logger.LogInformation("External login authentication failed");
                throw new Exception("External authentication error");
            }

            return result;
        }

        private async Task<IActionResult> ExternalLoginProcess(AuthenticateResult result, String returnUrl)
        {
            // Validate that the user couold be located from the external result
            var (user, provider, providerUserId) = await FindUserFromExternalProviderAsync(result);
            if (user == null)
            {
                throw new ApplicationException("ExternalLoginProcess failure.  User not found");
            }

            // this allows us to collect any additonal claims or properties
            // for the specific prtotocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user
            // we must issue the cookie maually, and can't use the SignInManager because
            // it doesn't expose an API to issue additional claims from the login workflow
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            additionalLocalClaims.AddRange(principal.Claims);

            var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.Id;
            var locked = await _userManager.IsLockedOutAsync(user).ConfigureAwait(false);
            var twofa = await _userManager.RequiresTwoFactorAuthentication(user).ConfigureAwait(false);

            if (locked == true)
            {
                return View("Lockout");
            }

            if (twofa == true)
            {
                // This allows two factor authentication for externally logged in users
                // Stripped from SignInOrTwoFactorAsync protect method within identity server
                var userId = await _userManager.GetUserIdAsync(user);
                
                var identity = new ClaimsIdentity(IdentityConstants.TwoFactorUserIdScheme);
                identity.AddClaim(new Claim(ClaimTypes.Name, userId));
                
                await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, new ClaimsPrincipal(identity));
                return RedirectToAction(nameof(Send), new { ReturnUrl = returnUrl, RememberMe = false });
            }

            // Sign into identity server, signout of external provider
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id, name));
            await _signInManager.SignInAsync(user, new AuthenticationProperties { });
            await _signInManager.SignoutExternalAsync(HttpContext);

            // Perform redirect
            if (returnUrl != null) { return Redirect(returnUrl); }
            else { return RedirectToAction("Index", new { controller = "Home" }); }

        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            var result = await ExternalLoginResult();
            var url = returnUrl != null ? returnUrl : result.Properties.RedirectUri != null ? result.Properties.RedirectUri : null;
            var (user, provider, providerUserId) = await FindUserFromExternalProviderAsync(result);

            if (provider == null || providerUserId == null)
            {
                await _signInManager.SignoutExternalAsync(HttpContext);
                throw new System.Exception("The provider and/or provider key could not be determined.");
            }

            var globalizer = CultureInfo.CurrentCulture.TextInfo;
            var claims = _claimManager.ExtractClaims(result);
            var roles = _claimManager.ExtractRoles(result);
            var domain = (claims.FirstOrDefault(a => a.Type == JwtClaimTypes.Email)?.Value ?? "").GetDomainName();
            var authorized = _providerManager.HasAuthorizedDomain(provider, domain);
            var restricted = _providerManager.HasRestrictedDomain(provider, domain);
            var requirements = _providerManager.GetRequireClaims(provider);
            var mode = _providerManager.GetLoginMode(provider);

            if (authorized == false)
            {
                await _signInManager.SignoutExternalAsync(HttpContext);
                throw new System.Exception("The externally provided email address violated the authorized domains policy");
            }

            if (restricted == true)
            {
                await _signInManager.SignoutExternalAsync(HttpContext);
                throw new System.Exception("The externally provided email address violates the restricted domains policy");
            }

            if (user == null)
            {
                if (mode == LoginMode.External)
                {
                    var userId = result.Principal.FindFirst(JwtClaimTypes.Subject) ?? result.Principal.FindFirst(ClaimTypes.NameIdentifier) ?? throw new Exception("Unknown userid");
                    var emailAddress = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.Email)?.Value;
                    var phoneNumber = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.PhoneNumber)?.Value;
                    var firstName = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.GivenName)?.Value;
                    var lastName = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.FamilyName)?.Value;
                    var nickName = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.NickName)?.Value;
                    var birthDate = claims.FirstOrDefault(a => a.Type == JwtClaimTypes.BirthDate) == null ? null : (DateTime?)Convert.ToDateTime(claims.FirstOrDefault(a => a.Type == JwtClaimTypes.BirthDate)?.Value);

                    var query = from a in requirements
                                join b in claims on a.ToLower() equals b.Type.ToLower() into temp
                                from c in temp.DefaultIfEmpty()
                                select new { Requirement = a, Claim = c };

                    if (query.Any(a => a.Claim == null))
                    {
                        return RedirectToAction("Signup", "Register", new { returnUrl = url });
                    }
                    else
                    {
                        user = await _accountManager.AutoCreateUserAsync(emailAddress, phoneNumber, firstName, lastName, nickName, birthDate, null, null, null, provider, userId.Value);
                        await _accountManager.AutoAssignRolesAsync(user, provider, domain, roles);
                        return await ExternalLoginProcess(result, url);
                    }
                }
                else
                {
                    return RedirectToAction("Signup", "Register", new { returnUrl = url });
                }
            }
            else
            {
                return await ExternalLoginProcess(result, url);
            }
        }

        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                // we will issue the external cookie and then redirect the
                // user back to the external callback, in essence, treating windows
                // auth the same as any other external authentication mechanism
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("Callback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // add the groups as claims -- be careful if the number of groups is too large
                if (AccountOptions.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                // trigger windows auth
                // since windows auth don't support the redirect uri,
                // this URL is re-triggered when we call challenge
                return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
            }
        }

        public async Task<String> GetProvider(ApplicationUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var logins = await _userManager.GetLoginsAsync(user);
            var provider = logins == null || logins.Count == 0 ? "Forms" : logins.First().LoginProvider;
            return provider;
        }

        private async Task<(ApplicationUser user, string provider, string providerUserId)> FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ?? externalUser.FindFirst(ClaimTypes.NameIdentifier) ?? throw new Exception("Unknown userid");
            var provider = result.Properties.Items.ContainsKey("scheme") == true ? result.Properties.Items["scheme"] : result.Properties.Items[".AuthScheme"];  // .AuthScheme is for ADFS
            var providerUserId = userIdClaim.Value;

            var claims = externalUser.Claims.ToList();
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);
            claims.Remove(userIdClaim);

            return (user, provider, providerUserId);
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }


        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private Task<ApplicationUser> GetCurrentUserAsync()
        {
            return _userManager.GetUserAsync(HttpContext.User);
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (String.IsNullOrEmpty((returnUrl ?? "").Trim()))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                return Redirect(returnUrl);
            }
        }
    }
}