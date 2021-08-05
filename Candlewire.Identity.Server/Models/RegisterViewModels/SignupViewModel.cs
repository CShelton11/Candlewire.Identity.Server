using Candlewire.Identity.Server.Attributes;
using Candlewire.Identity.Server.Enums;
using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.RegisterViewModels
{
    public class SignupViewModel: BaseViewModel
    {
        [EmailAddress]
        [Display(Name = "Email Address")]
        public String EmailAddress { get; set; }

        [EmailAddress]
        [Display(Name = "Phone Number")]
        public String PhoneNumber { get; set; }

        [Display(Name = "First Name")]
        public String FirstName { get; set; }

        [Display(Name = "Last Name")]
        public String LastName { get; set; }

        [Display(Name = "Nickname")]
        public String Nickname { get; set; }

        [Display(Name = "Date Of Birth")]
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }

        public String ShippingStreet { get; set; }
        public String ShippingCity { get; set; }
        public String ShippingState { get; set; }
        public String ShippingZip { get; set; }
        public String BillingStreet { get; set; }
        public String BillingCity { get; set; }
        public String BillingState { get; set; }
        public String BillingZip { get; set; }

        [RegularExpression("^((?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])|(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[^a-zA-Z0-9])|(?=.*?[A-Z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])|(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])).{9,}$", ErrorMessage = "Passwords must be at least 9 characters and contain at 3 of 4 of the following: upper case (A-Z), lower case (a-z), number (0-9) and special character (e.g. !@#$%^&*)")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public String Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match")]
        public String ConfirmPassword { get; set; }

        public String ReturnUrl { get; set; }
        public LoginMode LoginMode { get; set; }
        public String EditableClaims { get; set; }
        public String VisibleClaims { get; set; }
        public String RequireClaims { get; set; }
    }
}
