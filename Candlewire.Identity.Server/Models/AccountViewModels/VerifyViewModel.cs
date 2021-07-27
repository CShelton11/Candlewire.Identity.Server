using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.AccountViewModels
{
    public class VerifyViewModel: BaseViewModel
    {
        [Required]
        public String Provider { get; set; }

        [Required]
        public String Code { get; set; }

        public String ReturnUrl { get; set; }

        [Display(Name = "Remember this browser?")]
        public Boolean RememberBrowser { get; set; }

        [Display(Name = "Remember me?")]
        public Boolean RememberMe { get; set; }
    }
}
