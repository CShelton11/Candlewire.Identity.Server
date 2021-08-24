using Candlewire.Identity.Server.Attributes;
using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Enums;
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
        private readonly ProviderManager _providerManager;
        private readonly IEmailSender _emailSender;
        private readonly TermSettings _termSettings;

        public RegisterController(
            SignInManager<ApplicationUser> signinManager,
            UserManager<ApplicationUser> userManager,
            AccountManager accountManager,
            SessionManager sessionManager,
            TokenManager tokenManager,
            ClaimManager claimManager,
            IEmailSender emailSender,
            IOptions<TermSettings> termSettings,
            ProviderManager providerManager
        )
        {
            _signinManager = signinManager;
            _userManager = userManager;
            _accountManager = accountManager;
            _sessionManager = sessionManager;
            _tokenManager = tokenManager;
            _claimManager = claimManager;
            _emailSender = emailSender;
            _termSettings = termSettings.Value;
            _providerManager = providerManager;
        }

        [HttpGet]
        public IActionResult Unavailable()
        {
            return View();
        }

        [HttpGet]
        [RequireParameter(new String[] { "returnUrl", "firstName", "lastName", "nickName", "birthDate", "emailAddress", "phoneNumber", "shippingStreet", "shippingCity", "shippingState", "shippingZip", "billingStreet", "billingCity", "billingState", "billingZip" })]
        public async Task<IActionResult> Signup(String returnUrl, String firstName, String lastName, String nickName, String birthDate, String emailAddress, String phoneNumber, String shippingStreet, String shippingCity, String shippingState, String shippingZip, String billingStreet, String billingCity, String billingState, String billingZip)
        {
            var result = await ExternalResultAsync();
            var provider = GetProvider(result);

            if (provider.ToLower() == "forms")
            {
                var settings = _providerManager.GetSettingsByProviderCode("forms");
                if (settings.RegistrationMode.ToLower() == "external")
                {
                    return RedirectToAction("Unavailable");
                }
            }

            var firstValue = (firstName ?? "").Trim();
            var lastValue = (lastName ?? "").Trim();
            var nickValue = (nickName ?? "").Trim();
            var birthValue = String.IsNullOrEmpty(birthDate) == true ? null : (DateTime?)DateTime.Parse(birthDate);
            var emailValue = (emailAddress ?? "").Trim();
            var phoneValue = (phoneNumber ?? "").Trim();
            var streetValue1 = (shippingStreet ?? "").Trim();
            var cityValue1 = (shippingCity ?? "").Trim();
            var stateValue1 = (shippingState ?? "").Trim();
            var zipValue1 = (shippingZip ?? "").Trim();
            var streetValue2 = (billingStreet ?? "").Trim();
            var cityValue2 = (billingCity ?? "").Trim();
            var stateValue2 = (billingState ?? "").Trim();
            var zipValue2 = (billingZip ?? "").Trim();
            var editables = String.Join(",", _providerManager.GetEditableClaims(provider).ToArray());
            var visibles = String.Join(",", _providerManager.GetVisibleClaims(provider).ToArray());
            var required = String.Join(",", _providerManager.GetRequireClaims(provider).ToArray());

            var model = new SignupViewModel()
            {
                ReturnUrl = returnUrl,
                FirstName = firstValue,
                LastName = lastValue,
                Nickname = nickValue,
                Birthdate = birthValue,
                EmailAddress = emailValue,
                PhoneNumber = phoneValue,
                ShippingStreet = streetValue1,
                ShippingCity = cityValue1,
                ShippingState = stateValue1,
                ShippingZip = zipValue1,
                BillingStreet = streetValue2,
                BillingCity = cityValue2,
                BillingState = stateValue2,
                BillingZip = zipValue2,
                LoginMode = LoginMode.Internal,
                EditableClaims = editables,
                RequireClaims = required,
                VisibleClaims = visibles
            };

            return View(model);
        }

        // ************************************************
        // Signup actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Signup(String returnUrl)
        {
            var result = await ExternalResultAsync();
            var provider = GetProvider(result);

            if (provider.ToLower() == "forms")
            {
                var settings = _providerManager.GetSettingsByProviderCode("forms");
                if (settings.RegistrationMode.ToLower() == "external")
                {
                    return RedirectToAction("Unavailable");
                }
            }

            var mode = _providerManager.GetLoginMode(provider);
            var model = new SignupViewModel() { ReturnUrl = returnUrl, LoginMode = mode };

            var editables = String.Join(",", _providerManager.GetEditableClaims(provider).ToArray());
            var visibles = String.Join(",", _providerManager.GetVisibleClaims(provider).ToArray());
            var required = String.Join(",", _providerManager.GetRequireClaims(provider).ToArray());

            if (mode == Enums.LoginMode.External || mode == Enums.LoginMode.Mixed)
            {
                var principal = result.Principal;
                var claims = _claimManager.ExtractClaims(result);
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value;
                var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value;

                model.FirstName = first;
                model.LastName = last;
                model.EmailAddress = email;
                model.VisibleClaims = visibles;
                model.EditableClaims = editables;
                model.RequireClaims = required;
            }
            else
            {
                model.VisibleClaims = visibles;
                model.EditableClaims = editables;
                model.RequireClaims = required;
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            var result = await ExternalResultAsync();
            var mode = model.LoginMode;
            var provider = GetProvider(result);

            if (provider.ToLower() == "forms")
            {
                var settings = _providerManager.GetSettingsByProviderCode("forms");
                if (settings.RegistrationMode.ToLower() == "external")
                {
                    return RedirectToAction("Unavailable");
                }
            }

            if ((result != null && mode == LoginMode.Internal) || (result == null && (mode == LoginMode.External || mode == LoginMode.Mixed)))
            {
                ModelState.AddModelError("", "Unauthorized registration flow detected");
                return View(model);
            }

            var firstValue = (model.FirstName ?? "").Trim();
            var lastValue = (model.LastName ?? "").Trim();
            var firstRequired = _providerManager.HasRequiredClaim(provider, "given_name");
            var lastRequired = _providerManager.HasRequiredClaim(provider, "family_name");
            if ((firstRequired == true || lastRequired == true) && (String.IsNullOrEmpty(firstValue) || String.IsNullOrEmpty(lastValue)))
            {
                ModelState.AddModelError("", "First and last name are required fields");
            }

            var emailValue = (model.EmailAddress ?? "").Trim();
            var emailRequired = _providerManager.HasRequiredClaim(provider, "email");
            if (emailRequired == true && String.IsNullOrEmpty(emailValue))
            {
                ModelState.AddModelError("", "Email Address is a required field");
            }

            var nickValue = (model.Nickname ?? "").Trim();
            var nickRequired = _providerManager.HasRequiredClaim(provider, "nickname");
            if (nickRequired == true && String.IsNullOrEmpty(nickValue))
            {
                ModelState.AddModelError("", "Nickname is a required field");
            }

            var birthValue = model.Birthdate;
            var birthRequired = _providerManager.HasRequiredClaim(provider, "birthdate");
            if (birthRequired == true && birthValue == null)
            {
                ModelState.AddModelError("", "Date of birth is a required field");
            }

            var passwordValue = (model.Password ?? "").Trim();
            var passwordRequired = mode == LoginMode.Mixed || mode == LoginMode.Internal ? true : false;
            if (passwordRequired == true && String.IsNullOrEmpty(passwordValue))
            {
                ModelState.AddModelError("", "Password is a required field");
            }

            var confirmValue = (model.ConfirmPassword ?? "").Trim();
            var confirmRequired = mode == LoginMode.Mixed || mode == LoginMode.Internal ? true : false;
            if (confirmRequired == true && String.IsNullOrEmpty(confirmValue))
            {
                ModelState.AddModelError("", "Confirm password is a required field");
            }

            var phoneValue = (model.PhoneNumber ?? "").Trim();
            var phoneRequired = _providerManager.HasRequiredClaim(provider, "phone_number");
            if (phoneRequired == true && String.IsNullOrEmpty(phoneValue))
            {
                ModelState.AddModelError("", "Phone number is a required field");
            }

            var streetValue1 = (model.ShippingStreet ?? "").Trim();
            var cityValue1 = (model.ShippingCity ?? "").Trim();
            var stateValue1 = (model.ShippingState ?? "").Trim();
            var zipValue1 = (model.ShippingZip ?? "").Trim();
            var shippingRequired = _providerManager.HasRequiredClaim(provider, "shipping_address");
            var shippingProvided = false;
            if (shippingRequired == true)
            {
                if (String.IsNullOrEmpty(streetValue1) || String.IsNullOrEmpty(cityValue1) || String.IsNullOrEmpty(stateValue1) || String.IsNullOrEmpty(zipValue1))
                {
                    ModelState.AddModelError("", "All shipping address fields are required");
                    shippingProvided = false;
                }
            }
            else
            {
                var total = (Convert.ToInt32(!String.IsNullOrEmpty(streetValue1)) + Convert.ToInt32(!String.IsNullOrEmpty(cityValue1)) + Convert.ToInt32(!String.IsNullOrEmpty(stateValue1)) + Convert.ToInt32(!String.IsNullOrEmpty(zipValue1)));
                if (total > 0 && total < 4)
                {
                    ModelState.AddModelError("", "All shipping address fields must be provided if an address is being entered");
                    shippingProvided = false;
                }
                else
                {
                    shippingProvided = true;
                }
            }

            var streetValue2 = (model.BillingStreet ?? "").Trim();
            var cityValue2 = (model.BillingCity ?? "").Trim();
            var stateValue2 = (model.BillingState ?? "").Trim();
            var zipValue2 = (model.BillingZip ?? "").Trim();
            var billingRequired = _providerManager.HasRequiredClaim(provider, "billing_address");
            var billingProvided = false;
            if (billingRequired == true)
            {
                if (String.IsNullOrEmpty(streetValue2) || String.IsNullOrEmpty(cityValue2) || String.IsNullOrEmpty(stateValue2) || String.IsNullOrEmpty(zipValue2))
                {
                    ModelState.AddModelError("", "All billing address fields are required");
                    billingProvided = false;
                }
            }
            else
            {
                var total = (Convert.ToInt32(!String.IsNullOrEmpty(streetValue2)) + Convert.ToInt32(!String.IsNullOrEmpty(cityValue2)) + Convert.ToInt32(!String.IsNullOrEmpty(stateValue2)) + Convert.ToInt32(!String.IsNullOrEmpty(zipValue2)));
                if (total > 0 && total < 4)
                {
                    ModelState.AddModelError("", "All billing address fields must be provided if an address is being entered");
                    billingProvided = false;
                }
                else
                {
                    billingProvided = true;
                }
            }

            if (String.IsNullOrEmpty(emailValue) == false)
            {
                var authorized = false;
                var restricted = false;
                var domain = model.EmailAddress.GetDomainName();
                authorized = _providerManager.HasAuthorizedDomain(provider, domain);
                restricted = _providerManager.HasRestrictedDomain(provider, domain);

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
            }

            var shippingData = shippingProvided == true ? JsonConvert.SerializeObject(new { Street = streetValue1, City = cityValue1, State = stateValue1, Zip = zipValue1 }) : null;
            var billingData = billingProvided == true ? JsonConvert.SerializeObject(new { Street = streetValue2, City = cityValue2, State = stateValue2, Zip = zipValue2 }) : null;

            if (ModelState.ErrorCount == 0)
            {
                if (mode == LoginMode.External)
                {
                    var reg = new UserRegistrationCache(mode, emailValue, phoneValue, firstValue, lastValue, nickValue, birthValue, shippingData, billingData, model.Password);
                    var user = await RegisterUser(reg);
                    return RedirectToAction("ExternalLoginCallback", "Account", new { ReturnUrl = model.ReturnUrl });
                }
                else
                {
                    var reg = new UserRegistrationCache(mode, emailValue, phoneValue, firstValue, lastValue, nickValue, birthValue, shippingData, billingData, model.Password);
                    await _sessionManager.AddAsync("UserRegistrationCache", reg, DateTime.UtcNow.AddMinutes(30));
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
                await _sessionManager.AddAsync("UserRegistrationCache", reg, DateTime.UtcNow.AddMinutes(30));

                if (String.IsNullOrEmpty((reg.EmailAddress ?? "")))
                {
                    var registration = await _sessionManager.GetAsync<UserRegistrationCache>("UserRegistrationCache");
                    await RegisterUser(registration);

                    if (registration.LoginMode == LoginMode.Internal)
                    {
                        return RedirectToLocal(model.ReturnUrl);
                    }
                    else
                    {
                        return RedirectToAction("ExternalLoginCallback", "Account", new { ReturnUrl = model.ReturnUrl });
                    }
                }
                else
                {
                    return RedirectToAction("Verify", new { emailAddress = model.TermsEmail, returnUrl = model.ReturnUrl });
                }
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
                    var registration = await _sessionManager.GetAsync<UserRegistrationCache>("UserRegistrationCache");
                    await RegisterUser(registration);

                    if (registration.LoginMode == LoginMode.Internal)
                    {
                        return RedirectToLocal(model.ReturnUrl);
                    }
                    else
                    {
                        return RedirectToAction("ExternalLoginCallback", "Account", new { ReturnUrl = model.ReturnUrl });
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Unable to verify your email address using the provided code");
                    return View("Verify", model);
                }
            }
        }

        private async Task<ApplicationUser> RegisterUser(UserRegistrationCache reg)
        {
            if (reg.LoginMode == LoginMode.Internal)
            {
                var terms = reg.TermsAgreement == false ? null : _termSettings.Path.Split(("\\").ToCharArray()).Last().ToString().Replace(".txt", "");
                var user = await _accountManager.AutoCreateUserAsync(reg.EmailAddress, reg.PhoneNumber, reg.FirstName, reg.LastName, reg.Nickname, reg.Birthdate, terms, reg.ShippingAddress, reg.BillingAddress, reg.Password);
                await _sessionManager.RemoveAsync("Registration");
                await _signinManager.PasswordSignInAsync(user, reg.Password, false, false);
                return user;
            }
            else
            {
                var result = await ExternalResultAsync();
                var claims = _claimManager.ExtractClaims(result);
                var roles = _claimManager.ExtractRoles(result);
                var providerName = GetProvider(result);
                var providerKey = GetProviderKey(result);
                var domainName = (claims.FirstOrDefault(a => a.Type == JwtClaimTypes.Email)?.Value ?? "").GetDomainName();

                var terms = reg.TermsAgreement == false ? null : _termSettings.Path.Split(("\\").ToCharArray()).Last().ToString().Replace(".txt", "");
                var user = await _accountManager.AutoCreateUserAsync(reg.EmailAddress, reg.PhoneNumber, reg.FirstName, reg.LastName, reg.Nickname, reg.Birthdate, terms, reg.ShippingAddress, reg.BillingAddress, providerName, providerKey, reg.Password);
                await _accountManager.AutoAssignRolesAsync(user, providerName, domainName, roles);
                await _sessionManager.RemoveAsync("Registration");
                return user;
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

        private String GetProvider(AuthenticateResult result)
        {
            if (result?.Succeeded == true)
            {
                var globalizer = CultureInfo.CurrentCulture.TextInfo;
                var provider = result.Properties.Items.ContainsKey("scheme") == true ? result.Properties.Items["scheme"] : result.Properties.Items[".AuthScheme"];  // .AuthScheme is for ADFS
                return globalizer.ToTitleCase(provider);
            }
            else
            {
                return "Forms";
            }
        }

        private String GetProviderKey(AuthenticateResult result)
        {
            if (result?.Succeeded == true)
            {
                var externalUser = result.Principal;
                var externalClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ?? externalUser.FindFirst(ClaimTypes.NameIdentifier);
                if (externalClaim == null)
                {
                    throw new System.Exception("Provider key is unavailable");
                }
                else
                {
                    return externalClaim.Value;
                }
            }
            else
            {
                throw new System.Exception("Provider key is unavailable");
            }
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
            if (String.IsNullOrEmpty((returnUrl ?? "").Trim()))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                return Redirect(returnUrl);
            }
        }

        private class UserRegistrationCache
        {
            public LoginMode LoginMode { get; set; }
            public String EmailAddress { get; set; }
            public String PhoneNumber { get; set; }
            public String FirstName { get; set; }
            public String LastName { get; set; }
            public String Nickname { get; set; }
            public DateTime? Birthdate { get; set; }
            public String Password { get; set; }
            public Boolean TermsAgreement { get; set; }
            public String ShippingAddress { get; set; }
            public String BillingAddress { get; set; }

            public UserRegistrationCache(LoginMode loginMode, String emailAddress, String phoneNumber, String firstName, String lastName, String nickName, DateTime? birthDate, String shippingAddress, String billingAddress, String password)
            {
                LoginMode = loginMode;
                EmailAddress = emailAddress;
                PhoneNumber = phoneNumber;
                FirstName = firstName;
                LastName = lastName;
                Nickname = nickName;
                Birthdate = birthDate;
                Password = password;
                TermsAgreement = false;
                ShippingAddress = shippingAddress;
                BillingAddress = billingAddress;
            }
        }
    }
}

