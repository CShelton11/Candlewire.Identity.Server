using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Candlewire.Identity.Server.Attributes;
using Candlewire.Identity.Server.Contexts;
using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Enums;
using Candlewire.Identity.Server.Extensions;
using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Models.ManageViewModels;
using Candlewire.Identity.Server.Settings;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace Candlewire.Identity.ServerControllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class ManageController : Controller
    {
        private readonly ApplicationDbContext _applicationContext;
        private readonly SessionManager _sessionManager;
        private readonly TokenManager _tokenManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ProviderManager _providerManager;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ILogger _logger;
        private readonly UrlEncoder _urlEncoder;

        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        private const string RecoveryCodesKey = nameof(RecoveryCodesKey);

        public ManageController(
            ApplicationDbContext applicationContext,
            SessionManager sessionManager,
            TokenManager tokenManager,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ProviderManager providerManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILogger<ManageController> logger,
            UrlEncoder urlEncoder
        )
        {
            _applicationContext = applicationContext;
            _sessionManager = sessionManager;
            _tokenManager = tokenManager;
            _userManager = userManager;
            _providerManager = providerManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _logger = logger;
            _urlEncoder = urlEncoder;
        }

        // ************************************************
        // Profile actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            var model = await BuildProfileViewModel();
            return View(model);
        }

        private async Task<ProfileViewModel> BuildProfileViewModel()
        {
            var provider = await GetProvider();
            var toast = await _sessionManager.GetAsync<ProfileToastCache>("ProfileToastCache", true);
            var editables = String.Join(",", _providerManager.GetEditableClaims(provider).ToArray());
            var visibles = String.Join(",", _providerManager.GetVisibleClaims(provider).ToArray());
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var lastName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("family_name"))?.Value;
            var firstName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("given_name"))?.Value;
            var fullName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("full_name"))?.Value;
            var userName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("preferred_username"))?.Value;
            var nickName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("nickname"))?.Value;
            var birthdate = claims.FirstOrDefault(a => a.Type.ToLower().Equals("birthdate"))?.Value;
            var billingAddress = claims.FirstOrDefault(a => a.Type.ToLower().Equals("billing_address"))?.Value;
            var shippingAddress = claims.FirstOrDefault(a => a.Type.ToLower().Equals("shipping_address"))?.Value;

            var model = new ProfileViewModel
            {
                FirstName = firstName,
                LastName = lastName,
                Username = userName,
                Nickname = nickName,
                Birthdate = birthdate == null ? null : (DateTime?)Convert.ToDateTime(birthdate),
                EmailAddress = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneConfirmed = user.PhoneNumberConfirmed,
                BillingAddress = billingAddress == null ? null : JsonConvert.DeserializeObject<AddressViewModel>(billingAddress),
                ShippingAddress = shippingAddress == null ? null : JsonConvert.DeserializeObject<AddressViewModel>(shippingAddress),
                EditableClaims = editables,
                VisibleClaims = visibles,
                ToastTitle = toast == null ? "" : toast.ToastTitle,
                ToastMessages = toast == null ? new List<String>() : toast.ToastMessages,
                ToastLevel = toast == null ? "" : toast.ToastLevel,
            };

            return model;
        }

        // ************************************************
        // Security actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Security()
        {
            var model = await BuildSecurityViewModel();
            return View(model);
        }

        private async Task<SecurityViewModel> BuildSecurityViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var toast = await _sessionManager.GetAsync<SecurityToastCache>("SecurityToastCache", true);
            
            var model = new SecurityViewModel
            {
                EmailAddress = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                ToastTitle = toast == null ? "" : toast.ToastTitle,
                ToastMessages = toast == null ? new List<String>() : toast.ToastMessages,
                ToastLevel = toast == null ? "" : toast.ToastLevel
            };

            return model;
        }

        //*************************************************
        // Email actions
        // Email differs from most claims in that it can not be removed
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Email()
        {
            var model = await BuildEmailViewModel();
            return View("Email", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Email(EmailViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var response = new JsonResponse<EmailViewModel>(model, "Email Address can not be externally updated", false);
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluateEmailViewModel(user, model);
                var action = user.Email == model.EmailAddress ? "none" : (String.IsNullOrEmpty(user.Email)) ? "add" : "replace";

                if (ModelState.IsValid)
                {
                    if (action == "add" || action == "replace")
                    {
                        var cache = new ClaimVerificationCache("email", result.EmailAddress);
                        await _sessionManager.AddAsync("ClaimVerificationCache", cache, DateTime.UtcNow.AddMinutes(5));
                        return RedirectToAction("Verify", new { type = "email", mode = "cache" });
                    }
                    else
                    {
                        var cache = new ProfileToastCache("Email Updated Successfully", "Your email address has been successfully updated", "success");
                        await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                        return RedirectToAction("Profile");
                    }
                }
                else
                {
                    return View(model);
                }
            }
        }

        private async Task<Boolean> SaveEmailViewModel(ApplicationUser user, EmailViewModel model)
        {
            try
            {
                user.Email = model.EmailAddress;
                user.NormalizedEmail = model.EmailAddress.ToUpper();
                user.EmailConfirmed = true;

                await _userManager.UpdateAsync(user);

                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        private async Task<EmailViewModel> EvaluateEmailViewModel(ApplicationUser user, EmailViewModel model)
        {
            try
            {
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "email");
                var require = _providerManager.HasRequiredClaim(provider, "email");
                var authorized = _providerManager.HasAuthorizedDomain(provider, model.EmailAddress.GetDomainName());
                var restricted = _providerManager.HasRestrictedDomain(provider, model.EmailAddress.GetDomainName());

                if (!ModelState.IsValid)
                {
                    return model;
                }

                if (editable == false)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the email address");
                    return model;
                }

                if (authorized == false)
                {
                    ModelState.AddModelError("", "The provided email address violates the authorized domains policy");
                    return model;
                }

                if (restricted == true)
                {
                    ModelState.AddModelError("", "The provided email address violates the restricted domains policy");
                    return model;
                }

                if (user.Email != model.EmailAddress)
                {
                    var entity = await _userManager.FindByEmailAsync(model.EmailAddress);
                    if (entity != null)
                    {
                        ModelState.AddModelError("", "Another account is already associated with this email address");
                        return model;
                    }
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<EmailViewModel> BuildEmailViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var model = new EmailViewModel
            {
                EmailAddress = Convert.ToString(user.Email)
            };
            return model;
        }

        // ************************************************
        // Name actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Name()
        {
            var model = await BuildNameViewModel();
            return View("Name", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Name(NameViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var result = await EvaluateNameViewModel(model);
                var errors = ModelState.GetErrors();
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveNameViewModel(user, model);
                var response = new JsonResponse<NameViewModel>() { Result = result, Errors = errors, Succeeded = succeeded };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluateNameViewModel(model);
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveNameViewModel(user, model);
                if (succeeded)
                {
                    var title = "Name Updated Successfully";
                    var message = "Your first and last name have been successfully updated";
                    var level = "success";
                    var cache = new ProfileToastCache(title, message, level);
                    await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                    return RedirectToAction("Profile");
                }
                else
                {
                    return View(model);
                }
            }
        }

        private async Task<Boolean> SaveNameViewModel(ApplicationUser user, NameViewModel model)
        {
            try
            {
                var claims = await _userManager.GetClaimsAsync(user);

                var firstKey = "given_name";
                var firstName = (model.FirstName ?? "").Trim();
                var firstClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(firstKey));
                var firstAction = "none";

                var lastKey = "family_name";
                var lastName = (model.LastName ?? "").Trim();
                var lastClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(lastKey));
                var lastAction = "none";

                var fullKey = "name";
                var fullName = String.IsNullOrEmpty(model.FirstName) || String.IsNullOrEmpty(model.LastName) ? "" : model.FirstName + " " + model.LastName;
                var fullClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(fullKey));
                var fullAction = "none";

                if (String.IsNullOrEmpty(firstName) && firstClaim != null) { firstAction = "remove"; }
                else if (!String.IsNullOrEmpty(firstName) && firstClaim == null) { firstAction = "add"; }
                else if (!String.IsNullOrEmpty(firstName) && firstClaim != null) { firstAction = "replace"; }

                if (String.IsNullOrEmpty(lastName) && lastClaim != null) { lastAction = "remove"; }
                else if (!String.IsNullOrEmpty(lastName) && lastClaim == null) { lastAction = "add"; }
                else if (!String.IsNullOrEmpty(lastName) && lastClaim != null) { lastAction = "replace"; }

                if (String.IsNullOrEmpty(fullName) && lastClaim != null) { fullAction = "remove"; }
                else if (!String.IsNullOrEmpty(fullName) && lastClaim == null) { fullAction = "add"; }
                else if (!String.IsNullOrEmpty(fullName) && lastClaim != null) { fullAction = "replace"; }

                if (firstAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(firstKey, firstName)); }
                else if (firstAction == "replace") { await _userManager.ReplaceClaimAsync(user, firstClaim, new System.Security.Claims.Claim(firstKey, firstName)); }
                else if (firstAction == "remove") { await _userManager.RemoveClaimAsync(user, firstClaim); }

                if (lastAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(lastKey, lastName)); }
                else if (lastAction == "replace") { await _userManager.ReplaceClaimAsync(user, lastClaim, new System.Security.Claims.Claim(lastKey, lastName)); }
                else if (lastAction == "remove") { await _userManager.RemoveClaimAsync(user, lastClaim); }

                if (fullAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(fullKey, fullName)); }
                else if (fullAction == "replace") { await _userManager.ReplaceClaimAsync(user, fullClaim, new System.Security.Claims.Claim(fullKey, fullName)); }
                else if (fullAction == "remove") { await _userManager.RemoveClaimAsync(user, fullClaim); }

                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        private async Task<NameViewModel> EvaluateNameViewModel(NameViewModel model)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "given_name") || _providerManager.HasEditableClaim(provider, "family_name");
                var required = _providerManager.HasRequiredClaim(provider, "given_name") || _providerManager.HasRequiredClaim(provider, "family_name");

                if (!ModelState.IsValid) 
                { 
                    return model; 
                }

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the first and last name");
                    return model;
                }

                if (required && (String.IsNullOrEmpty((model.FirstName ?? "").Trim()) || String.IsNullOrEmpty((model.LastName ?? "").Trim())))
                {
                    ModelState.AddModelError("", "First and last name are required fields");
                    return model;
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<NameViewModel> BuildNameViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var claims = await _userManager.GetClaimsAsync(user);
            var firstName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("given_name"))?.Value;
            var lastName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("family_name"))?.Value;

            var model = new NameViewModel
            {
                FirstName = firstName,
                LastName = lastName
            };

            return model;
        }

        //*************************************************
        // Username actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Username()
        {
            var model = await BuildUsernameViewModel();
            return View("Username", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Username(UsernameViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var result = await EvaluateUsernameViewModel(user, model);
                var errors = ModelState.GetErrors();
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveUsernameViewModel(user, model);
                var response = new JsonResponse<UsernameViewModel>() { Result = result, Errors = errors, Succeeded = succeeded };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluateUsernameViewModel(user, model);
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveUsernameViewModel(user, model);
                if (succeeded)
                {
                    var title = "Username Updated Successfully";
                    var message = "Your username has been successfully updated";
                    var level = "success";
                    var cache = new ProfileToastCache(title, message, level);
                    await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                    return RedirectToAction("Profile");
                }
                else
                {
                    return View(model);
                }
            }
        }

        private async Task<Boolean> SaveUsernameViewModel(ApplicationUser user, UsernameViewModel model)
        {
            try
            {
                var claims = await _userManager.GetClaimsAsync(user);

                var userKey = "preferred_username";
                var userName = (model.Username ?? "").Trim();
                var userClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(userKey));
                var userAction = "none";

                if (String.IsNullOrEmpty(userName) && userClaim != null) { userAction = "remove"; }
                else if (!String.IsNullOrEmpty(userName) && userClaim == null) { userAction = "add"; }
                else if (!String.IsNullOrEmpty(userName) && userClaim != null) { userAction = "replace"; }

                if (userAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(userKey, userName)); }
                else if (userAction == "replace") { await _userManager.ReplaceClaimAsync(user, userClaim, new System.Security.Claims.Claim(userKey, userName)); }
                else if (userAction == "remove") { await _userManager.RemoveClaimAsync(user, userClaim); }

                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        private async Task<UsernameViewModel> EvaluateUsernameViewModel(ApplicationUser user, UsernameViewModel model)
        {
            try
            {
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "preferred_username");
                var required = _providerManager.HasRequiredClaim(provider, "preferred_username");

                if (!ModelState.IsValid) 
                { 
                    return model; 
                }

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the username");
                    return model;
                }

                if (required && String.IsNullOrEmpty((model.Username ?? "").Trim()))
                {
                    ModelState.AddModelError("", "Username is a required field");
                    return model;
                }

                var taken = _applicationContext.UserClaims.Any(a => a.ClaimType == "preferred_username" && a.ClaimValue == model.Username && a.UserId != user.Id);
                if (taken)
                {
                    ModelState.AddModelError("", "This username has already been taken");
                    return model;
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<UsernameViewModel> BuildUsernameViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var claims = await _userManager.GetClaimsAsync(user);
            var userName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("preferred_username"))?.Value;

            var model = new UsernameViewModel
            {
                Username = userName
            };

            return model;
        }

        //*************************************************
        // Nickname actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Nickname()
        {
            var model = await BuildNicknameViewModel();
            return View("Nickname", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Nickname(NicknameViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var result = await EvaluateNicknameViewModel(model);
                var errors = ModelState.GetErrors();
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveNicknameViewModel(user, result);
                var response = new JsonResponse<NicknameViewModel>() { Result = result, Errors = errors, Succeeded = succeeded };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluateNicknameViewModel(model);
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveNicknameViewModel(user, result);
                if (succeeded)
                {
                    var title = "Nickname Updated Successfully";
                    var message = "Your nickname has been successfully updated";
                    var level = "success";
                    var cache = new ProfileToastCache(title, message, level);
                    await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                    return RedirectToAction("Profile");
                }
                else
                {
                    return View(model);
                }
            }
        }

        public async Task<Boolean> SaveNicknameViewModel(ApplicationUser user, NicknameViewModel model)
        {
            try
            {
                var claims = await _userManager.GetClaimsAsync(user);

                var nickKey = "nickname";
                var nickName = model.Nickname;
                var nickClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(nickKey));
                var nickAction = "none";

                if (String.IsNullOrEmpty(nickName) && nickClaim != null) { nickAction = "remove"; }
                else if (!String.IsNullOrEmpty(nickName) && nickClaim == null) { nickAction = "add"; }
                else if (!String.IsNullOrEmpty(nickName) && nickClaim != null) { nickAction = "replace"; }

                if (nickAction == "add") { await _userManager.AddClaimAsync(user, new Claim(nickKey, nickName)); }
                else if (nickAction == "replace") { await _userManager.ReplaceClaimAsync(user, nickClaim, new Claim(nickKey, nickName)); }
                else if (nickAction == "remove") { await _userManager.RemoveClaimAsync(user, nickClaim); }

                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        public async Task<NicknameViewModel> EvaluateNicknameViewModel(NicknameViewModel model)
        {
            try
            {
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "nickname");
                var required = _providerManager.HasRequiredClaim(provider, "nickname");

                if (!ModelState.IsValid) 
                { 
                    return model; 
                }

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the nickname");
                    return model;
                }

                if (required && String.IsNullOrEmpty((model.Nickname).Trim()))
                {
                    ModelState.AddModelError("", "Nickname is a required field");
                    return model;
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<NicknameViewModel> BuildNicknameViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var claims = await _userManager.GetClaimsAsync(user);
            var nickName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("nickname"))?.Value;

            var model = new NicknameViewModel
            {
                Nickname = nickName
            };

            return model;
        }

        //*************************************************
        // Birthdate actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Birthdate()
        {
            var model = await BuildBirthdateViewModel();
            return View("Birthdate", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Birthdate(BirthdateViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var result = await EvaluateBirthdateViewModel(model);
                var errors = ModelState.GetErrors();
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveBirthdateViewModel(user, result);
                var response = new JsonResponse<BirthdateViewModel>() { Result = result, Errors = errors, Succeeded = succeeded };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluateBirthdateViewModel(model);
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveBirthdateViewModel(user, result);
                if (succeeded)
                {
                    var title = "Date Of Birth Updated Successfully";
                    var message = "Your date of birth has been successfully updated";
                    var level = "success";
                    var cache = new ProfileToastCache(title, message, level);
                    await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                    return RedirectToAction("Profile");
                }
                else
                {
                    return View(model);
                }
            }
        }

        private async Task<Boolean> SaveBirthdateViewModel(ApplicationUser user, BirthdateViewModel model)
        {
            try
            {
                var claims = await _userManager.GetClaimsAsync(user);

                var birthKey = "birthdate";
                var birthDate = model.Birthdate;
                var birthClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(birthKey));
                var birthAction = "none";

                if (birthDate == null && birthClaim != null) { birthAction = "remove"; }
                else if (birthDate != null && birthClaim == null) { birthAction = "add"; }
                else if (birthDate != null && birthClaim != null) { birthAction = "replace"; }

                if (birthAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(birthKey, birthDate.ToString())); }
                else if (birthAction == "replace") { await _userManager.ReplaceClaimAsync(user, birthClaim, new System.Security.Claims.Claim(birthKey, birthDate.ToString())); }
                else if (birthAction == "remove") { await _userManager.RemoveClaimAsync(user, birthClaim); }

                return true;
            }
            catch(Exception)
            {
                return false;
            }
        }

        private async Task<BirthdateViewModel> EvaluateBirthdateViewModel(BirthdateViewModel model)
        {
            try
            {
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "birthdate");
                var required = _providerManager.HasRequiredClaim(provider, "birthdate");

                if (!ModelState.IsValid) 
                { 
                    return model; 
                }

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the date of birth");
                    return model;
                }

                if (required && model.Birthdate == null)
                {
                    ModelState.AddModelError("", "Date of birth is a required field");
                    return model;
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<BirthdateViewModel> BuildBirthdateViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var claims = await _userManager.GetClaimsAsync(user);
            var birthDate = claims.FirstOrDefault(a => a.Type.ToLower().Equals("birthdate"))?.Value;
            DateTime? defaultDate = null;

            var model = new BirthdateViewModel
            {
                Birthdate = (birthDate == null) ? defaultDate : Convert.ToDateTime(birthDate)
            };

            return model;
        }

        //*************************************************
        // Address actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Address(String type)
        {
            var types = new String[] { "billing_address", "shipping_address" };
            if (!types.Contains(type))
            {
                ModelState.AddModelError("", "Only billing address and shipping address types are allowed");
                return RedirectToAction("Profile");
            }
            else
            {
                var model = await BuildAddressViewModel(type);
                return View("Address", model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Address(AddressViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var result = await EvaluateAddressViewModel(model);
                var errors = ModelState.GetErrors();
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveAddressViewModel(user, result);
                var response = new JsonResponse<AddressViewModel>() { Result = result, Errors = errors, Succeeded = succeeded };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluateAddressViewModel(model);
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SaveAddressViewModel(user, result);
                if (succeeded)
                {
                    var title = "Address Updated Successfully";
                    var message = "Your address info was succesfully updated";
                    var level = "success";
                    var cache = new ProfileToastCache(title, message, level);
                    await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                    return RedirectToAction("Profile");
                }
                else
                {
                    return View(model);
                }
            }
        }

        private async Task<Boolean> SaveAddressViewModel(ApplicationUser user, AddressViewModel model)
        {
            try
            {
                var claims = await _userManager.GetClaimsAsync(user);
                var address = claims.FirstOrDefault(a => a.Type.ToLower().Equals(model.Type));
                var action = "none";

                if (String.IsNullOrEmpty((model.Street ?? "").Trim())) { action = "remove"; }
                else if (address == null) { action = "add"; }
                else if (address != null) { action = "replace"; }

                if (action == "replace") { await _userManager.ReplaceClaimAsync(user, address, new Claim(model.Type, JsonConvert.SerializeObject(model))); }
                else if (action == "add") { await _userManager.AddClaimAsync(user, new Claim(model.Type, JsonConvert.SerializeObject(model))); }
                else if (action == "remove") { await _userManager.RemoveClaimAsync(user, address); }

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private async Task<AddressViewModel> EvaluateAddressViewModel(AddressViewModel model)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, model.Type);
                var required = _providerManager.HasRequiredClaim(provider, model.Type);
                var types = new String[] { "billing_address", "shipping_address" };

                if (!types.Contains(model.Type))
                {
                    ModelState.AddModelError("", "Only billing address and shipping address types are allowed");
                    return model;
                }

                if (!ModelState.IsValid) 
                { 
                    return model; 
                }

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing this type of address");
                    return model;
                }

                var street = (model.Street ?? "").Trim();
                var city = (model.City ?? "").Trim();
                var state = (model.State ?? "").Trim();
                var zip = (model.Zip ?? "").Trim();
                if (required == true)
                {
                    if (String.IsNullOrEmpty(street) || String.IsNullOrEmpty(city) || String.IsNullOrEmpty(state) || String.IsNullOrEmpty(zip))
                    {
                        ModelState.AddModelError("", "All address fields are required");
                        return model;
                    }
                }
                else
                {
                    var total = (Convert.ToInt32(!String.IsNullOrEmpty(street)) + Convert.ToInt32(!String.IsNullOrEmpty(city)) + Convert.ToInt32(!String.IsNullOrEmpty(state)) + Convert.ToInt32(!String.IsNullOrEmpty(zip)));
                    if (total > 0 && total < 4)
                    {
                        ModelState.AddModelError("", "All address fields are required when an address is being provided");
                        return model;
                    }
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<AddressViewModel> BuildAddressViewModel(String type)
        {
            var user = await _userManager.GetUserAsync(User);
            var claims = await _userManager.GetClaimsAsync(user);
            var address = claims.FirstOrDefault(a => a.Type.ToLower().Equals(type.ToLower()));
            var model = new AddressViewModel() { };
            if (address == null)
            {
                return new AddressViewModel() { Type = type };
            }
            else
            {
                return JsonConvert.DeserializeObject<AddressViewModel>(address.Value);
            }
        }

        //*************************************************
        // Phone actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Phone()
        {
            var model = await BuildPhoneViewModel();
            return View("Phone", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Phone(PhoneViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var result = await EvaluatePhoneViewModel(model);
                var errors = ModelState.GetErrors();
                var passed = ModelState.IsValid;
                var (succeeded, action) = passed == false ? (false, null) : await SavePhoneViewModel(user, result);
                var response = new JsonResponse<PhoneViewModel>() { Result = result, Errors = errors, Succeeded = succeeded };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluatePhoneViewModel(model);
                var passed = ModelState.IsValid;
                var (succeeded, action) = passed == false ? (false, null) : await SavePhoneViewModel(user, result);
                if (succeeded)
                {
                    if (action == "add" || action == "replace")
                    {
                        var cache = new ClaimVerificationCache("phone", result.PhoneNumber);
                        await _sessionManager.AddAsync("ClaimVerificationCache", cache, DateTime.UtcNow.AddMinutes(5));
                        return RedirectToAction("Verify", new { type = "phone", mode = "cache" });
                    }
                    else if (action == "none")
                    {
                        var cache = new ProfileToastCache("Phone Updated Successfully", "Your phone number has been successfully updated", "success");
                        await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                        return RedirectToAction("Profile");
                    }
                    else
                    {
                        var cache = new ProfileToastCache("Phone Removed Successfully", "Your phone number has been successfully removed", "success");
                        await _sessionManager.AddAsync("ProfileToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                        return RedirectToAction("Profile");
                    }
                }
                else
                {
                    return View(model);
                }
            }
        }

        private async Task<(Boolean, String)> SavePhoneViewModel(ApplicationUser user, PhoneViewModel model)
        {
            try
            {
                var claims = await _userManager.GetClaimsAsync(user);
                var phone = model.PhoneNumber;
                var action = "none";

                if (phone == user.PhoneNumber) { action = "none"; }
                else if (String.IsNullOrEmpty(phone) && !String.IsNullOrEmpty(user.PhoneNumber)) { action = "remove"; }
                else if (!String.IsNullOrEmpty(phone) && String.IsNullOrEmpty(user.PhoneNumber)) { action = "add"; }
                else if (!String.IsNullOrEmpty(phone) && !String.IsNullOrEmpty(user.PhoneNumber)) { action = "replace"; }

                if (action == "add" || action == "replace")
                {
                    user.PhoneNumber = phone;
                    user.PhoneNumberConfirmed = false;
                }
                else if (action == "remove")
                {
                    user.PhoneNumber = null;
                    user.PhoneNumberConfirmed = false;
                }

                await _userManager.UpdateAsync(user);
                return (true, action);
            }
            catch (Exception)
            {
                return (false, null);
            }
        }

        private async Task<PhoneViewModel> EvaluatePhoneViewModel(PhoneViewModel model)
        {
            try
            {
                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "phone_number");
                var required = _providerManager.HasRequiredClaim(provider, "phone_number");

                if (!ModelState.IsValid) 
                { 
                    return model; 
                }

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the phone number");
                    return model;
                }

                if (required && String.IsNullOrEmpty((model.PhoneNumber ?? "").Trim()))
                {
                    ModelState.AddModelError("", "Phone number is a required field");
                    return model;
                }

                return model;
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return model;
            }
        }

        private async Task<PhoneViewModel> BuildPhoneViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            var phoneNumber = user.PhoneNumber;

            var model = new PhoneViewModel
            {
                PhoneNumber = Convert.ToString(phoneNumber)
            };

            return model;
        }

        // ************************************************
        // Password actions
        // ************************************************
        [HttpGet]
        public async Task<IActionResult> Password()
        {
            var user = await _userManager.GetUserAsync(User);
            var model = BuildPasswordViewModel();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Password(PasswordViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var format = HttpContext.Request.Query["Format"].ToString();

            if (format == "json")
            {
                var errors = new String[] { "Password can not be updated externally" };
                var response = new JsonResponse<PasswordViewModel>() { Result = new PasswordViewModel(), Errors = errors.ToList(), Succeeded = false };
                return new JsonResult(response);
            }
            else
            {
                var result = await EvaluatePasswordViewModel(model);
                var passed = ModelState.IsValid;
                var succeeded = passed == false ? false : await SavePasswordViewModel(user, result);
                if (succeeded)
                {
                    var cache = new SecurityToastCache("Password Updated Successfully", "Your password has been successfully updated", "success");
                    await _sessionManager.AddAsync("SecurityToastCache", cache, DateTime.UtcNow.AddMinutes(1));
                    return RedirectToAction("Security");
                }
                else
                {
                    ModelState.AddModelError("", "An unexpected error occurred while updating your password.");
                    return View(model);
                }
            }
        }

        private async Task<Boolean> SavePasswordViewModel(ApplicationUser user, PasswordViewModel model)
        {
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return true;
            }
            else
            {
                return false;
            }
        }

        private async Task<PasswordViewModel> EvaluatePasswordViewModel(PasswordViewModel model)
        {
            var provider = await GetProvider();
            var mode = _providerManager.GetLoginMode(provider);

            if (!ModelState.IsValid)
            {
                return model;
            }

            if (mode == LoginMode.External)
            {
                ModelState.AddModelError("", "Passwords can not be configured for this account type");
                return model;
            }

            return model;
        }

        private PasswordViewModel BuildPasswordViewModel()
        {
            return new PasswordViewModel();
        }

        // ************************************************
        // Verification actions
        // ************************************************
        [HttpGet]
        public async Task<ActionResult> Verify(String type, String mode)
        {
            var user = await _userManager.GetUserAsync(User);
            var cache = await _sessionManager.GetAsync<ClaimVerificationCache>("ClaimVerificationCache");

            if ((mode == "cache" && cache != null) || (mode == "user" && user != null))
            {
                var email = type == "email" ? (mode == "cache" ? cache.ClaimValue : user.Email) : null;
                var phone = type == "phone" ? (mode == "cache" ? cache.ClaimValue : user.PhoneNumber) : null;

                if (type == "email")
                {
                    var code = await _tokenManager.GenerateVerifyEmailTokenAsync();
                    var subject = "Email Verification";
                    var message = $"Email Verification - Please use the following code to verify this email address: {code} (Expires in 5 minutes)";
                    await _emailSender.SendEmailAsync(email, subject, message);
                }
                else
                {
                    var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, phone);
                    var message = $"Candlewire - Phone Verification - Please use the following code to verify this phone number: {code} (Expires in 5 minutes)";
                    await _smsSender.SendSmsAsync(phone, message);
                }

                return View("Verify", new VerifyViewModel() { VerificationType = type, VerificationMode = mode, VerificationEmail = email, VerificationPhone = phone });
            }
            else if (mode == "cache" && cache == null)
            {
                var title = "Verification Timeout";
                var message = "The verification code timed out.  Please try again.";
                var level = "failure";
                await _sessionManager.AddAsync("ProfileToastCache", new ProfileToastCache(title, message, level), DateTime.UtcNow.AddMinutes(1));
                return RedirectToAction("Profile");
            }
            else
            {
                var title = "Unexpected Error Occurred";
                var message = "An unexpected error has occurred during the update process";
                var level = "failure";
                await _sessionManager.AddAsync("ProfileToastCache", new ProfileToastCache(title, message, level), DateTime.UtcNow.AddMinutes(1));
                return RedirectToAction("Profile");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Verify(VerifyViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            var type = model.VerificationType;
            var mode = model.VerificationMode;
            var cache = await _sessionManager.GetAsync<ClaimVerificationCache>("ClaimVerificationCache");

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (String.IsNullOrEmpty(model.VerificationCode))
            {
                ModelState.AddModelError("", "Verification code is required");
                return View(model);
            }

            if ((mode == "cache" && cache != null) || (mode == "user" && user != null))
            {
                var email = type == "email" ? (mode == "cache" ? cache.ClaimValue : user.Email) : null;
                var phone = type == "phone" ? (mode == "cache" ? cache.ClaimValue : user.PhoneNumber) : null;
                var token = model.VerificationCode;

                if (type == "email")
                {
                    var verified = await _tokenManager.VerifyEmailTokenAsync(token);
                    var succeeded = verified = false ? false : await SaveEmailViewModel(user, new EmailViewModel() { EmailAddress = email });

                    if (verified == false)
                    {
                        ModelState.AddModelError("", "Unable to verify the email using the provided code");
                        return View(model);
                    }

                    if (succeeded == true)
                    {
                        var title = "Email Successfully Verified";
                        var message = "Your email address was successfully verified";
                        var level = "failure";
                        await _sessionManager.AddAsync("ProfileToastCache", new ProfileToastCache(title, message, level), DateTime.UtcNow.AddMinutes(1));
                        return RedirectToAction("Profile");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Unable to verify the email address at this time");
                        return View(model);
                    }
                }
                else
                {
                    var result = await _userManager.ChangePhoneNumberAsync(user, user.PhoneNumber, model.VerificationCode);
                    if (result.Succeeded)
                    {
                        var title = "Phone Successfully Verfied";
                        var message = "Your phone number was successfully verified";
                        var level = "success";
                        await _sessionManager.AddAsync("ProfileToastCache", new ProfileToastCache(title, message, level), DateTime.UtcNow.AddMinutes(1));
                        return RedirectToAction("Profile");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Unable to verify the phone number at this time.  Please try again");
                        return View("Verify", model);
                    }
                }
            }
            else if (mode == "cache" && cache == null)
            {
                var title = "Verification Timeout Occurred";
                var message = "Your verification code timed out.  Please try again.";
                var level = "failure";
                await _sessionManager.AddAsync("ProfileToastCache", new ProfileToastCache(title, message, level), DateTime.UtcNow.AddMinutes(1));
                return RedirectToAction("Profile");
            }
            else
            {
                var title = "Unexpected Error Occurred";
                var message = "An unexpected error has occurred during the verification process.  Please try again.";
                var level = "failure";
                await _sessionManager.AddAsync("ProfileToastCache", new ProfileToastCache(title, message, level), DateTime.UtcNow.AddMinutes(1));
                return RedirectToAction("Profile");
            }
        }

        // ************************************************
        // Two factor authentication actions
        // ************************************************
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.SetTwoFactorEnabledAsync(user, true);

            if (user != null)
            {
                await _signInManager.RefreshSignInAsync(user);
            }
            return RedirectToAction("Security", "Manage");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (user != null)
            {
                await _signInManager.RefreshSignInAsync(user);
            }
            return RedirectToAction("Security", "Manage");
        }

        // ************************************************
        // Helper methods
        // ************************************************
        public async Task<String> GetProvider()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }
            var claims = await _userManager.GetClaimsAsync(user);
            var logins = await _userManager.GetLoginsAsync(user);
            var provider = logins == null || logins.Count == 0 ? "Forms" : logins.First().LoginProvider;
            return provider;
        }

        // ************************************************
        // Json response class
        // ************************************************
        public class JsonResponse<T>
        {
            public T Result { get; set; }
            public Boolean Succeeded { get; set; }
            public List<String> Errors { get; set; }

            public JsonResponse() { }

            public JsonResponse(T result, List<String> errors, Boolean succeeded)
            {
                Result = result;
                Errors = errors;
                Succeeded = succeeded;
            }

            public JsonResponse(T result, String error, Boolean succeeded)
            {
                Result = result;
                Errors = (new String[] { error }).ToList();
                Succeeded = succeeded;
            }
        }

        public class ProfileToastCache
        {
            public String ToastTitle { get; set; }
            public List<String> ToastMessages { get; set; }
            public String ToastLevel { get; set; }

            public ProfileToastCache() { }

            public ProfileToastCache(String toastTitle, String toastMessage, String toastLevel)
            {
                ToastTitle = toastTitle ?? "";
                ToastMessages = String.IsNullOrEmpty(toastMessage) ? new List<String>() : (new String[] { toastMessage }).ToList();
                ToastLevel = toastLevel ?? "";
            }

            public ProfileToastCache(String toastTitle, List<String> toastMessages, String toastLevel)
            {
                ToastTitle = toastTitle ?? "";
                ToastMessages = toastMessages ?? new List<String>();
                ToastLevel = toastLevel ?? "";
            }
        }

        public class SecurityToastCache
        {
            public String ToastTitle { get; set; }
            public List<String> ToastMessages { get; set; }
            public String ToastLevel { get; set; }

            public SecurityToastCache() { }

            public SecurityToastCache(String toastTitle, String toastMessage, String toastLevel)
            {
                ToastTitle = toastTitle ?? "";
                ToastMessages = String.IsNullOrEmpty(toastMessage) ? new List<String>() : (new String[] { toastMessage }).ToList();
                ToastLevel = toastLevel ?? "";
            }

            public SecurityToastCache(String toastTitle, List<String> toastMessages, String toastLevel)
            {
                ToastTitle = toastTitle ?? "";
                ToastMessages = toastMessages ?? new List<String>();
                ToastLevel = toastLevel ?? "";
            }
        }

        public class ClaimVerificationCache
        {
            public String ClaimValue { get; set; }
            public String ClaimType { get; set; }

            public ClaimVerificationCache() { }

            public ClaimVerificationCache(String claimType, String claimValue)
            {
                ClaimType = claimType;
                ClaimValue = claimValue;
            }
        }
    }
}
