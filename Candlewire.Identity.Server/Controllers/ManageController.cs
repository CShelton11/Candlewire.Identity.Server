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
using Candlewire.Identity.Server.Extensions;
using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Models.ManageViewModels;
using Candlewire.Identity.Server.Settings;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
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

        [HttpGet]
        [RequireParameter(new String[] { "toastTitle", "toastLevel", "toastData" })]
        public async Task<IActionResult> Profile(String toastTitle, String toastLevel, String toastData)
        {
            var model = await BuildProfileViewModel();

            var toastBytes = Convert.FromBase64String(toastData);
            var toastJson = System.Text.Encoding.UTF8.GetString(toastBytes);
            var toastArray = JsonConvert.DeserializeObject<List<String>>(toastJson);

            model.ToastTitle = toastTitle;
            model.ToastMessages = toastArray;
            model.ToastLevel = toastLevel;
            return View("Profile", model);
        }

        private async Task<ProfileViewModel> BuildProfileViewModel()
        {
            var provider = await GetProvider();
            var editables = String.Join(",", _providerManager.GetEditableClaims(provider).ToArray());
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
                EditableClaims = editables
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

        [HttpGet]
        [RequireParameter(new String[] { "toastTitle", "toastLevel", "toastData" })]
        public async Task<IActionResult> Security(String toastTitle, String toastLevel, String toastData)
        {
            var model = await BuildSecurityViewModel();

            var toastBytes = Convert.FromBase64String(toastData);
            var toastJson = System.Text.Encoding.UTF8.GetString(toastBytes);
            var toastArray = JsonConvert.DeserializeObject<List<String>>(toastJson);

            model.ToastTitle = toastTitle;
            model.ToastMessages = toastArray;
            model.ToastLevel = toastLevel;

            return View("Security", model);
        }

        private async Task<SecurityViewModel> BuildSecurityViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var model = new SecurityViewModel
            {
                EmailAddress = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled
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
            try
            {
                if (!ModelState.IsValid) { return View(model); }

                var user = await _userManager.GetUserAsync(User);
                if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "given_name") || _providerManager.HasEditableClaim(provider, "family_name");
                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the first and last name");
                    return View(model);
                }

                var claims = await _userManager.GetClaimsAsync(user);

                var firstKey = "given_name";
                var firstName = model.FirstName;
                var firstClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(firstKey));
                var firstAction = String.IsNullOrEmpty(firstName) && firstClaim != null ? "remove" : firstClaim == null ? "add" : firstName == firstClaim.Value ? "none" : "replace";

                var lastKey = "family_name";
                var lastName = model.LastName;
                var lastClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(lastKey));
                var lastAction = String.IsNullOrEmpty(lastName) && lastClaim != null ? "remove" : lastClaim == null ? "add" : lastName == lastClaim.Value ? "none" : "replace";

                var fullKey = "name";
                var fullName = String.IsNullOrEmpty(model.FirstName) || String.IsNullOrEmpty(model.LastName) ? "" : model.FirstName + " " + model.LastName;
                var fullClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(fullKey));
                var fullAction = String.IsNullOrEmpty(fullName) && fullClaim != null ? "remove" : (fullClaim == null ? "add" : fullName == fullClaim.Value ? "none" : "replace");

                if (firstAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(firstKey, firstName)); }
                else if (firstAction == "replace") { await _userManager.ReplaceClaimAsync(user, firstClaim, new System.Security.Claims.Claim(firstKey, firstName)); }
                else if (firstAction == "remove") { await _userManager.RemoveClaimAsync(user, firstClaim); }

                if (lastAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(lastKey, lastName)); }
                else if (lastAction == "replace") { await _userManager.ReplaceClaimAsync(user, lastClaim, new System.Security.Claims.Claim(lastKey, lastName)); }
                else if (lastAction == "remove") { await _userManager.RemoveClaimAsync(user, lastClaim); }

                if (fullAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(fullKey, fullName)); }
                else if (fullAction == "replace") { await _userManager.ReplaceClaimAsync(user, fullClaim, new System.Security.Claims.Claim(fullKey, fullName)); }
                else if (fullAction == "remove") { await _userManager.RemoveClaimAsync(user, fullClaim); }

                var toastTitle = "Name Updated Successful";
                var toastMessages = new List<String>((new String[] { "Your name has been successfully updated" }));
                var toastJson = JsonConvert.SerializeObject(toastMessages);
                var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                var toastLevel = "success";
                return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
            }
            catch(Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return View("Name", model);
            }
        }

        private async Task<NameViewModel> BuildNameViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

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
            try
            {
                if (!ModelState.IsValid) { return View(model); }

                var user = await _userManager.GetUserAsync(User);
                if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "preferred_username");

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the username");
                    return View(model);
                }

                var claims = await _userManager.GetClaimsAsync(user);

                var userKey = "preferred_username";
                var userName = model.Username;
                var userClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(userKey));
                var userAction = String.IsNullOrEmpty(userName) && userClaim != null ? "remove" : (userClaim == null ? "add" : userName == userClaim.Value ? "none" : "replace");

                var exists = _applicationContext.UserClaims.Where(a => a.ClaimValue == model.Username && a.UserId != user.Id).Count();
                if (exists > 0)
                {
                    ModelState.AddModelError("", "This username has already been taken");
                    return View("Username", model);
                }

                if (userAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(userKey, userName)); }
                else if (userAction == "replace") { await _userManager.ReplaceClaimAsync(user, userClaim, new System.Security.Claims.Claim(userKey, userName)); }
                else if (userAction == "remove") { await _userManager.RemoveClaimAsync(user, userClaim); }

                var toastTitle = "Username Updated Successful";
                var toastMessages = new List<String>((new String[] { "Your username has been successfully updated" }));
                var toastJson = JsonConvert.SerializeObject(toastMessages);
                var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                var toastLevel = "success";
                return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return View("Username", model);
            }
        }

        private async Task<UsernameViewModel> BuildUsernameViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

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
            try
            {
                if (!ModelState.IsValid) { return View(model); }

                var user = await _userManager.GetUserAsync(User);
                if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "nickname");

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the nickname");
                    return View(model);
                }

                var claims = await _userManager.GetClaimsAsync(user);

                var nickKey = "nickname";
                var nickName = model.Nickname;
                var nickClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(nickKey));
                var nickAction = String.IsNullOrEmpty(nickName) && nickClaim != null ? "remove" : (nickClaim == null ? "add" : nickName == nickClaim.Value ? "none" : "replace");

                if (nickAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(nickKey, nickName)); }
                else if (nickAction == "replace") { await _userManager.ReplaceClaimAsync(user, nickClaim, new System.Security.Claims.Claim(nickKey, nickName)); }
                else if (nickAction == "remove") { await _userManager.RemoveClaimAsync(user, nickClaim); }

                var toastTitle = "Nickname Updated Successful";
                var toastMessages = new List<String>((new String[] { "Your nickname has been successfully updated" }));
                var toastJson = JsonConvert.SerializeObject(toastMessages);
                var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                var toastLevel = "success";
                return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return View("Name", model);
            }
        }

        private async Task<NicknameViewModel> BuildNicknameViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

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
            try
            {
                if (!ModelState.IsValid) { return View(model); }

                var user = await _userManager.GetUserAsync(User);
                if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "birthdate");

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the date of birth");
                    return View(model);
                }

                var claims = await _userManager.GetClaimsAsync(user);

                var birthKey = "birthdate";
                var birthDate = model.Birthdate;
                var birthClaim = claims.FirstOrDefault(a => a.Type.ToLower().Equals(birthKey));
                var birthValue = birthClaim == null ? null : (DateTime?)Convert.ToDateTime(birthClaim.Value);
                var birthAction = birthDate == null && birthClaim != null ? "remove" : (birthClaim == null ? "add" : birthDate == birthValue ? "none" : "replace");

                if (birthAction == "add") { await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim(birthKey, birthDate.ToString())); }
                else if (birthAction == "replace") { await _userManager.ReplaceClaimAsync(user, birthClaim, new System.Security.Claims.Claim(birthKey, birthDate.ToString())); }
                else if (birthAction == "remove") { await _userManager.RemoveClaimAsync(user, birthClaim); }

                var toastTitle = "Date Of Birth Updated Successful";
                var toastMessages = new List<String>((new String[] { "Your date of birth has been successfully updated" }));
                var toastJson = JsonConvert.SerializeObject(toastMessages);
                var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                var toastLevel = "success";
                return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return View("Birthdate", model);
            }
        }

        private async Task<BirthdateViewModel> BuildBirthdateViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

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
            if (type == "billing_address" || type == "shipping_address")
            {
                var model = await BuildAddressViewModel(type);
                return View("Address", model);
            }
            else
            {
                return RedirectToAction("Profile");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Address(AddressViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, model.Type);

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing this type of address");
                    return View(model);
                }

                var claims = await _userManager.GetClaimsAsync(user);
                var address = claims.FirstOrDefault(a => a.Type.ToLower().Equals(model.Type));

                if (address != null)
                {
                    var claim = new Claim(model.Type, JsonConvert.SerializeObject(model.ToSerializable()));
                    await _userManager.ReplaceClaimAsync(user, address, claim);

                    var toastTitle = "Address Updated Successfully";
                    var toastMessages = new List<String>((new String[] { "Your address was succesfully updated" }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "success";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
                else
                {
                    var claim = new Claim(model.Type, JsonConvert.SerializeObject(model.ToSerializable()));
                    await _userManager.AddClaimAsync(user, claim);

                    var toastTitle = "Address Added Successfully";
                    var toastMessages = new List<String>((new String[] { "Your address was succesfully added" }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "success";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
            }
            else
            {
                return View("Address", model);
            }
        }

        private async Task<AddressViewModel> BuildAddressViewModel(String type)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

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
        // Email actions
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
            try
            {
                if (!ModelState.IsValid) { return View(model); }

                var user = await _userManager.GetUserAsync(User);
                if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "email");
                var authorized = _providerManager.HasAuthorizedDomain(provider, model.EmailAddress.GetDomainName());
                var restricted = _providerManager.HasRestrictedDomain(provider, model.EmailAddress.GetDomainName());

                if (editable == false)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the email address");
                    return View("Email", model);
                }

                if (authorized == false)
                {
                    ModelState.AddModelError("", "The provided email address violated the authorized domains policy");
                    return View("Email", model);
                }

                if (restricted == true)
                {
                    ModelState.AddModelError("", "The provided email address violates the restricted domains policy");
                    return View("Email", model);
                }

                var emailMessages = new List<String>();
                var emailAddress = model.EmailAddress;
                var emailAction = "none";
                if (String.IsNullOrEmpty(emailAddress) && !String.IsNullOrEmpty(user.Email))
                {
                    emailAction = "remove";
                }
                else if (!String.IsNullOrEmpty(emailAddress))
                {
                    if (String.IsNullOrEmpty(user.Email))
                    {
                        emailAction = "add";
                    }
                    else if (emailAddress != user.Email)
                    {
                        emailAction = "replace";
                    }
                }

                if (emailAction == "add" || emailAction == "replace")
                {
                    dynamic data = new ExpandoObject();
                    data.EmailAddress = emailAddress;
                    data.EmailAction = emailAction;
                    await _sessionManager.AddAsync("EmailVerificationObject", data, DateTime.UtcNow.AddMinutes(5));
                    return RedirectToAction("Verify", new { verificationType = "email" });
                }
                else if (emailAction == "remove")
                {
                    user.Email = null;
                    user.NormalizedEmail = null;
                    user.EmailConfirmed = false;

                    await _userManager.UpdateAsync(user);
                    await _signInManager.RefreshSignInAsync(user);

                    var toastTitle = "Email Removed Successfully";
                    var toastMessages = new List<String>((new String[] { "Your email was succesfully removed" }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "success";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
                else if (emailAction == "none")
                {
                    var toastTitle = "Email Updated Successfully";
                    var toastMessages = new List<String>((new String[] { "Your email address has been successfully updated" }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "success";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
                else
                {
                    ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                    return View("Email", model);
                }
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return View("Email", model);
            }
        }

        private async Task<EmailViewModel> BuildEmailViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var emailAddress = user.Email;
            var model = new EmailViewModel
            {
                EmailAddress = Convert.ToString(emailAddress)
            };

            return model;
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
            try
            {
                if (!ModelState.IsValid) { return View(model); }

                var user = await _userManager.GetUserAsync(User);
                if (user == null) { throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'."); }

                var provider = await GetProvider();
                var editable = _providerManager.HasEditableClaim(provider, "phone_number");

                if (!editable)
                {
                    ModelState.AddModelError("", "This account is restricted from editing the phone number");
                    return View(model);
                }

                var claims = await _userManager.GetClaimsAsync(user);

                var phoneMessages = new List<String>();
                var phoneNumber = model.PhoneNumber;
                var phoneAction = "none";
                if (String.IsNullOrEmpty(phoneNumber) && !String.IsNullOrEmpty(user.PhoneNumber))
                {
                    phoneAction = "remove";
                }
                else if (!String.IsNullOrEmpty(phoneNumber))
                {
                    if (String.IsNullOrEmpty(user.PhoneNumber))
                    {
                        phoneAction = "add";
                    }
                    else if (phoneNumber != user.PhoneNumber)
                    {
                        phoneAction = "replace";
                    }
                }

                if (phoneAction == "add" || phoneAction == "replace")
                {
                    user.PhoneNumber = phoneNumber;
                    user.PhoneNumberConfirmed = false;
                    await _userManager.UpdateAsync(user);
                    await _signInManager.RefreshSignInAsync(user);
                    return RedirectToAction("Verify", new { verificationType = "phone" });
                }
                else if (phoneAction == "remove")
                {
                    user.PhoneNumber = null;
                    user.PhoneNumberConfirmed = false;
                    await _userManager.UpdateAsync(user);
                    await _signInManager.RefreshSignInAsync(user);

                    var toastTitle = "Phone Removed Successfully";
                    var toastMessages = new List<String>((new String[] { "Your phone number has been successfully removed" }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "success";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
                else if (phoneAction == "none")
                {
                    var toastTitle = "Phone Updated Successfully";
                    var toastMessages = new List<String>((new String[] { "Your phone number has been successfully updated" }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "success";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
                else
                {
                    ModelState.AddModelError("", "An unexpected error occurred while updating you information.  Please try again");
                    return View("Phone", model);
                }
            }
            catch (Exception)
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your information.  Please try again");
                return View("Phone", model);
            }
        }

        private async Task<PhoneViewModel> BuildPhoneViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var phoneNumber = user.PhoneNumber;
            var model = new PhoneViewModel
            {
                PhoneNumber = Convert.ToString(phoneNumber)
            };

            return model;
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
        // Verification actions
        // ************************************************
        [HttpGet]
        public async Task<ActionResult> Verify(String verificationType)
        {
            var user = await _userManager.GetUserAsync(User);
            try
            {
                var phone = user.PhoneNumber;
                var email = user.Email;

                if (verificationType.ToLower() == "email")
                {
                    dynamic data = await _sessionManager.GetAsync<ExpandoObject>("EmailVerificationObject");
                    var code = await _tokenManager.GenerateVerifyEmailTokenAsync();
                    var subject = "Candlewire Email Verification";
                    var message = $"Candlewire - Email Verification - Please use the following code to verify this email address: {code}";
                    await _emailSender.SendEmailAsync(data.EmailAddress, subject, message);
                }
                else
                {
                    var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, user.PhoneNumber);
                    var message = $"Candlewire - Phone Verification - Please use the following code to verify this phone number: {code}";
                    await _smsSender.SendSmsAsync(user.PhoneNumber, message);
                }

                return View("Verify", new VerifyViewModel() { VerificationType = verificationType, VerificationEmail = user.Email, VerificationPhone = user.PhoneNumber });
            }
            catch (Exception)
            {
                if (verificationType.ToLower() == "email")
                {
                    var toastTitle = "Verification Email Failed";
                    var toastMessages = new List<String>((new String[] { "Unable to send the verification email at this time.  Please try again later." }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "failure";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
                else
                {
                    var toastTitle = "Verification Text Message Failed";
                    var toastMessages = new List<String>((new String[] { "Unable to send the verification text message at this time.  Please try again later." }));
                    var toastJson = JsonConvert.SerializeObject(toastMessages);
                    var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                    var toastLevel = "failure";
                    return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                }
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Verify(VerifyViewModel model)
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
                var user = await _userManager.GetUserAsync(User);
                if (model.VerificationType.ToLower() == "email")
                {
                    var token = model.VerificationCode;
                    var verified = await _tokenManager.VerifyEmailTokenAsync(token);
                    dynamic data = await _sessionManager.GetAsync<System.Dynamic.ExpandoObject>("EmailVerificationObject");

                    if (verified == true && data != null)
                    {
                        user.Email = data.EmailAddress;
                        user.NormalizedEmail = data.EmailAddress.ToUpper();
                        user.EmailConfirmed = true;
                        await _userManager.UpdateAsync(user);
                        await _signInManager.RefreshSignInAsync(user);
                        var emailAction = data.EmailAction;
                        var toastTitle = "Verification Succeeded";
                        var toastMessages = new List<String>((new String[] { "Email succesfully verified" }));
                        var toastJson = JsonConvert.SerializeObject(toastMessages);
                        var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                        var toastLevel = "success";
                        return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                    }
                    else
                    {
                        ModelState.AddModelError("", "Unable to verify the email address at this time.  Please try again");
                        return View("Verify", model);
                    }
                }
                else
                {
                    var result = await _userManager.ChangePhoneNumberAsync(user, user.PhoneNumber, model.VerificationCode);
                    if (result.Succeeded)
                    {
                        await _signInManager.RefreshSignInAsync(user);
                        var toastTitle = "Verification Succeeded";
                        var toastMessages = new List<String>((new String[] { "Phone number successfully verified" }));
                        var toastJson = JsonConvert.SerializeObject(toastMessages);
                        var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                        var toastLevel = "success";
                        return RedirectToAction("Profile", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
                    }
                    else
                    {
                        ModelState.AddModelError("", "Unable to verify the phone number at this time.  Please try again");
                        return View("Verify", model);
                    }
                }
            }
        }

        // ************************************************
        // Password actions
        // ************************************************

        [HttpGet]
        public async Task<IActionResult> Password()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            return View(new PasswordViewModel { });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Password(PasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (changePasswordResult.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                _logger.LogInformation("User changed their password successfully.");

                var toastTitle = "Password Update Successful";
                var toastMessages = new List<String>((new String[] { "Your password has been successfully updated" }));
                var toastJson = JsonConvert.SerializeObject(toastMessages);
                var toastData = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(toastJson));
                var toastLevel = "success";
                return RedirectToAction("Security", new { toastTitle = toastTitle, toastLevel = toastLevel, toastData = toastData });
            }
            else
            {
                ModelState.AddModelError("", "An unexpected error occurred while updating your password.");
                return View("Password", model);
            }
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




    }
}
