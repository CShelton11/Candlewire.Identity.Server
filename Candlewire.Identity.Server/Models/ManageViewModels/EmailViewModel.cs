using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class EmailViewModel: BaseViewModel
    {
        [Required(ErrorMessage = "Email Address is a required field")]
        [EmailAddress]
        [Display(Name = "Email Address")]
        public String EmailAddress { get; set; }
    }
}
