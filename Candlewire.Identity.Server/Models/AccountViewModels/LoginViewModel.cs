using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.ComponentModel.DataAnnotations;

namespace Candlewire.Identity.Server.Models.AccountViewModels
{
    public class LoginViewModel : BaseViewModel
    {
        [Display(Name = "Email Address")]
        public String Email { get; set; }

        [Display(Name = "Password")]
        public String Password { get; set; }

        public String StepNumber { get; set; }
        public Boolean RememberLogin { get; set; }
        public String ReturnUrl { get; set; }
    }
}
