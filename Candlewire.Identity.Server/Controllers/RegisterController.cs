using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Extensions;
using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Models.RegisterViewModels;
using IdentityModel;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
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
        private readonly IEmailSender _emailSender;

        public RegisterController(SignInManager<ApplicationUser> signinManager, UserManager<ApplicationUser> userManager, AccountManager accountManager, SessionManager sessionManager, TokenManager tokenManager, IEmailSender emailSender)
        {
            _signinManager = signinManager;
            _userManager = userManager;
            _accountManager = accountManager;
            _sessionManager = sessionManager;
            _tokenManager = tokenManager;
            _emailSender = emailSender;
        }

        [HttpGet]
        public async Task<IActionResult> Signup(String returnUrl)
        {
            var result = await ExternalResult();
            var model = new SignupViewModel() { ReturnUrl = returnUrl, AccountSource = "internal" };
            if (result != null)
            {
                var principal = result.Principal;
                var claims = principal.Claims.ToList();

                var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
                var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
                var upn = claims.FirstOrDefault(a => a.Type == ClaimTypes.Upn)?.Value;
                var array = name.Split(" ");

                if (first == null && array.Length > 1) { first = array[0]; }
                if (last == null && array.Length > 1) { last = array[1]; }
                if (email == null && upn != null) { email = upn; }

                model.FirstName = first;
                model.LastName = last;
                model.EmailAddress = email;
                model.AccountSource = "external";
            }
            
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            if (ModelState.IsValid)
            {
                DateTime year = DateTime.Now;
                TimeSpan timespan = year - Convert.ToDateTime(model.Birthdate);
                DateTime age = DateTime.MinValue.AddDays(timespan.Days);
                Int32 years = age.Year - 1;
                if (years < 18)
                {
                    ModelState.AddModelError("", "You must be at least 18 years of age to create an account");
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
                var model = new TermsViewModel();
                var directory = Directory.GetCurrentDirectory();
                var path = directory + "\\Documents\\Terms.txt";
                var terms = "";
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
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
                    var subject = "Candlewire Email Verification";
                    var message = $"Candlewire - Email Verification - Please use the following code to verify this email address: {code}";
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
                    var user = await _accountManager.AutoCreateUserAsync(reg.EmailAddress, reg.FirstName, reg.LastName, reg.Nickname, Convert.ToDateTime(reg.Birthdate), reg.Password);
                    await _accountManager.AutoAssignRolesAsync(user);
                    await _sessionManager.RemoveAsync("Registration");

                    if (reg.AccountSource == "candlewire")
                    {
                        await _signinManager.PasswordSignInAsync(user, reg.Password, false, false);
                        return RedirectToLocal(model.ReturnUrl);
                    }
                    else
                    {
                        return RedirectToAction("ExternalLoginCallback", "Account", new { ReturnUrl = model.ReturnUrl});
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

        private async Task<AuthenticateResult> ExternalResult()
        {
            AuthenticateResult result = null;
            AuthenticateResult resultA = await AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            AuthenticateResult resultB = await AuthenticateAsync(IdentityConstants.ExternalScheme);

            if (resultA?.Succeeded == true) { result = resultA; }
            else if (resultB?.Succeeded == true) { result = resultB; }
            return result;
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
