using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Extensions;
using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Models.RegisterViewModels;
using Candlewire.Identity.Server.Settings;
using IdentityModel;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Controllers
{
    [Route("[controller]/[action]")]
    public class RegisterController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signinManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AccountManager _accountManager;
        private readonly SessionManager _sessionManager;
        private readonly TokenManager _tokenManager;
        private readonly ClaimManager _claimManager;
        private readonly IEmailSender _emailSender;
        private readonly TermSettings _termSettings;
        private readonly ProviderSettings _providerSettings;

        public RegisterController(SignInManager<ApplicationUser> signinManager, UserManager<ApplicationUser> userManager, AccountManager accountManager, SessionManager sessionManager, TokenManager tokenManager, ClaimManager claimManager, IEmailSender emailSender, IOptions<TermSettings> termSettings, IOptions<ProviderSettings> providerSettings)
        {
            _signinManager = signinManager;
            _userManager = userManager;
            _accountManager = accountManager;
            _sessionManager = sessionManager;
            _tokenManager = tokenManager;
            _claimManager = claimManager;
            _emailSender = emailSender;
            _termSettings = termSettings.Value;
            _providerSettings = providerSettings.Value;
        }

        [HttpGet]
        public async Task<IActionResult> Signup(String returnUrl)
        {
            var result = await ExternalResultAsync();
            var source = result == null ? "internal" : "external";
            var model = new SignupViewModel() { ReturnUrl = returnUrl, AccountSource = source };

            if (source == "external")
            {
                var principal = result.Principal;
                var claims = _claimManager.ExtractClaims(result);

                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value;
                var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value;

                model.FirstName = first;
                model.LastName = last;
                model.EmailAddress = email;
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await ExternalResultAsync();
                var external = (await ExternalResultAsync())?.Succeeded;
                var source = model.AccountSource;
                var authorized = false;
                var restricted = false;

                if ((external == true && source == "internal") || (external == false && source == "external"))
                {
                    ModelState.AddModelError("", "Unauthorized registration flow detected");
                    return View(model);
                }

                if (external == true)
                {
                    var (provider, providerKey) = ExternalProviderAsync(result);
                    var globalizer = CultureInfo.CurrentCulture.TextInfo;
                    var settings = (ProviderSetting)_providerSettings.GetType().GetProperty(globalizer.ToTitleCase(provider))?.GetValue(_providerSettings, null);
                    var domain = model.EmailAddress.GetDomainName();
                    authorized = settings.HasAuthorizedDomain(domain);
                    restricted = settings.HasRestrictedDomain(domain);
                }
                else
                {
                    var settings = _providerSettings.Forms;
                    var domain = model.EmailAddress.GetDomainName();
                    authorized = settings.HasAuthorizedDomain(domain);
                    restricted = settings.HasRestrictedDomain(domain);
                }

                if (authorized == false)
                {
                    ModelState.AddModelError("", "The provided email address violated the authorized domains policy");
                }

                if (restricted == true)
                {
                    ModelState.AddModelError("", "The provided email address violates the restricted domains policy");
                }

                var exists = _userManager.Users.Count(a => a.Email.ToUpper() == model.EmailAddress.ToUpper()) != 0;
                if (exists == true)
                {
                    ModelState.AddModelError("", "This email address is already associated with an account.");
                }

                if (ModelState.ErrorCount == 0)
                {
                    await _sessionManager.AddAsync("UserRegistrationCache", new UserRegistrationCache(model.AccountSource, model.EmailAddress, model.FirstName, model.LastName, model.Nickname, model.Birthdate, model.Password) { }, DateTime.UtcNow.AddMinutes(10));
                    return RedirectToAction("Terms", new { emailAddress = model.EmailAddress, returnUrl = model.ReturnUrl });
                }
            }

            model.Password = "";
            model.ConfirmPassword = "";
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Terms(String emailAddress, String returnUrl)
        {
            var reg = await _sessionManager.GetAsync<UserRegistrationCache>("UserRegistrationCache");
            if (reg != null)
            {
                var path = Directory.GetCurrentDirectory();
                var file = path + _termSettings.Path;
                var model = new TermsViewModel();
                var terms = "";
                using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        terms = reader.ReadToEnd();
                    }
                }

                model.TermsHtml = "<div>" + terms + "</div>";
                model.TermsEmail = emailAddress;
                model.ReturnUrl = returnUrl;
                return View(model);
            }
            else
            {
                var html = "<div class=\"col-md-12\">Whoops.  Something happened during the signup process and we can't find any account information.</div>" +
                           "<div class=\"col-md-12\">This can happen if you waited too long to finish your account setup.</div>";
                return RedirectToAction("Issue", "Register", new { issue = html });
            }
        }

        [HttpPost]
        public async Task<IActionResult> Terms(TermsViewModel model)
        {
            var reg = await _sessionManager.GetAsync<UserRegistrationCache>("UserRegistrationCache");
            if (reg != null)
            {
                reg.TermsAgreement = true;
                await _sessionManager.AddAsync("UserRegistrationCache", reg, DateTime.UtcNow.AddMinutes(10));
                return RedirectToAction("Verify", new { emailAddress = model.TermsEmail, returnUrl = model.ReturnUrl });
            }
            else
            {
                var html = "<div class=\"col-md-12\">Whoops.  Something happened during the signup process and we can't find any account information.</div>" +
                           "<div class=\"col-md-12\">This can happen if you waited too long to finish your account setup.</div>";
                return RedirectToAction("Issue", "Register", new { issue = html });
            }
        }

        [HttpGet]
        public IActionResult Issue(String issue)
        {
            var model = new IssueViewModel() { IssueHtml = issue };
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Verify(String emailAddress, String returnUrl)
        {
            var reg = await _sessionManager.GetAsync<UserRegistrationCache>("UserRegistrationCache");
            if (reg != null)
            {
                if (reg.TermsAgreement == true)
                {
                    var code = await _tokenManager.GenerateVerifyEmailTokenAsync();
                    var subject = "Email Verification";
                    var message = $"Email Verification - Please use the following code to verify this email address: {code}";
                    await _emailSender.SendEmailAsync(emailAddress, subject, message);
                    var model = new VerifyViewModel() { VerificationEmail = emailAddress, ReturnUrl = returnUrl };
                    return View(model);
                }
                else
                {
                    return RedirectToAction("Terms", new { emailAddress = emailAddress, returnUrl = returnUrl });
                }
            }
            else
            {
                var html = "<div class=\"col-md-12\">Whoops.  Something happened during the signup process and we can't find any account information.</div>" +
                           "<div class=\"col-md-12\">This can happen if you waited too long to finish your account setup.</div>";
                return RedirectToAction("Issue", "Register", new { issue = html });
            }
        }

        [HttpPost]
        public async Task<IActionResult> Verify(VerifyViewModel model)
        {
            System.Threading.Thread.Sleep(2000);
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (String.IsNullOrEmpty(model.VerificationCode))
            {
                ModelState.AddModelError("", "Verification code is required");
                return View(model);
            }
            else
            {
                var token = model.VerificationCode;
                var verified = await _tokenManager.VerifyEmailTokenAsync(token);
                if (verified == true)
                {
                    var reg = await _sessionManager.GetAsync<UserRegistrationCache>("UserRegistrationCache");
                    if (reg.AccountSource == "internal")
                    {
                        var user = await _accountManager.AutoCreateUserAsync(reg.EmailAddress, reg.FirstName, reg.LastName, reg.Nickname, reg.Birthdate, _termSettings.Path.Split(("\\").ToCharArray()).Last().ToString().Replace(".txt", ""), reg.Password);
                        await _sessionManager.RemoveAsync("Registration");
                        await _signinManager.SignInAsync(user, new AuthenticationProperties { });
                        return RedirectToLocal(model.ReturnUrl);
                    }
                    else
                    {
                        var result = await ExternalResultAsync();
                        var claims = _claimManager.ExtractClaims(result);
                        var roles = _claimManager.ExtractRoles(result);
                        var userId = result.Principal.FindFirst(JwtClaimTypes.Subject) ?? result.Principal.FindFirst(ClaimTypes.NameIdentifier) ?? throw new Exception("Unknown userid");
                        var providerName = result.Properties.Items.ContainsKey("scheme") == true ? result.Properties.Items["scheme"] : result.Properties.Items[".AuthScheme"];
                        var providerKey = userId.Value;
                        var domainName = (claims.FirstOrDefault(a => a.Type == JwtClaimTypes.Email)?.Value ?? "").GetDomainName();

                        var user = await _accountManager.AutoCreateUserAsync(reg.EmailAddress, reg.FirstName, reg.LastName, reg.Nickname, reg.Birthdate, _termSettings.Path.Split(("\\").ToCharArray()).Last().ToString().Replace(".txt", ""), providerName, providerKey, reg.Password);
                        await _accountManager.AutoAssignRolesAsync(user, providerName, domainName, roles);
                        await _sessionManager.RemoveAsync("Registration");
                        return RedirectToAction("ExternalLoginCallback", "Account", new { ReturnUrl = model.ReturnUrl });
                    }
                }
                else
                {
                    model.ToastTitle = "Verification Failed";
                    model.ToastMessages = new List<String>((new String[] { "Unable to verify the email address.", "Please try again." }));
                    model.ToastLevel = "failure";
                    return View("Verify", model);
                }
            }
        }

        private async Task<AuthenticateResult> ExternalResultAsync()
        {
            AuthenticateResult result = null;
            AuthenticateResult resultA = await AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            AuthenticateResult resultB = await AuthenticateAsync(IdentityConstants.ExternalScheme);

            if (resultA?.Succeeded == true) { result = resultA; }
            else if (resultB?.Succeeded == true) { result = resultB; }
            return result;
        }

        private (string provider, string providerKey) ExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ?? externalUser.FindFirst(ClaimTypes.NameIdentifier) ?? throw new Exception("Unknown userid");
            var provider = result.Properties.Items.ContainsKey("scheme") == true ? result.Properties.Items["scheme"] : result.Properties.Items[".AuthScheme"];  // .AuthScheme is for ADFS
            var providerUserId = userIdClaim.Value;
            return (provider, providerUserId);
        }

        private async Task<AuthenticateResult> AuthenticateAsync(String scheme)
        {
            try
            {
                return await HttpContext.AuthenticateAsync(scheme);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        private class UserRegistrationCache
        {
            public String AccountSource { get; set; }
            public String EmailAddress { get; set; }
            public String FirstName { get; set; }
            public String LastName { get; set; }
            public String Nickname { get; set; }
            public DateTime? Birthdate { get; set; }
            public String Password { get; set; }
            public Boolean TermsAgreement { get; set; }

            public UserRegistrationCache(String accountSource, String emailAddress, String firstName, String lastName, String nickName, DateTime? birthDate, String password)
            {
                AccountSource = accountSource;
                EmailAddress = emailAddress;
                FirstName = firstName;
                LastName = lastName;
                Nickname = nickName;
                Birthdate = birthDate;
                Password = password;
                TermsAgreement = false;
            }
        }
    }
}

