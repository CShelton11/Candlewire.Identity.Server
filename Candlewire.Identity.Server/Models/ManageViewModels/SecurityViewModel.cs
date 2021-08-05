using Candlewire.Identity.Server.Enums;
using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class SecurityViewModel: BaseViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email Address")]
        public String EmailAddress { get; set; }

        [Required]
        [Display(Name = "Email Confirmed")]
        public Boolean EmailConfirmed { get; set; }

        [Phone]
        [RegularExpression(@"^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$", ErrorMessage = "Not a valid phone number")]
        [Display(Name = "Phone Number")]
        public String PhoneNumber { get; set; }

        [Required]
        [Display(Name = "Phone Number Confirmed")]
        public Boolean PhoneConfirmed { get; set; }

        [Required]
        [Display(Name = "Two Factor Authentication")]
        public Boolean? TwoFactorEnabled { get; set; }

        public LoginMode LoginMode { get; set; }
    }
}