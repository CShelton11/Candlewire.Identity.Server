using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.RegisterViewModels
{
    public class VerifyViewModel: BaseViewModel
    {
        public String ReturnUrl { get; set; }

        [Display(Name = "Email Address")]
        [EmailAddress]
        public String VerificationEmail { get; set; }

        [Display(Name = "Verification Code")]
        public String VerificationCode { get; set; }
    }
}
