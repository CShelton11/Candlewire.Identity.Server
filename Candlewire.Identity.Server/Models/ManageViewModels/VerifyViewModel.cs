using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class VerifyViewModel: BaseViewModel
    {
        [Required]
        public String VerificationType { get; set; }

        [Required]
        public String VerificationMode { get; set; }

        [Display(Name = "Verification Code")]
        public String VerificationCode { get; set; }
        
        public String VerificationEmail { get; set; }
        
        public String VerificationPhone { get; set; }
    }
}
