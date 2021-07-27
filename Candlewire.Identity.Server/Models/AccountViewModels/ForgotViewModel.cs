using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.ComponentModel.DataAnnotations;

namespace Candlewire.Identity.Server.Models.AccountViewModels
{
    public class ForgotViewModel: BaseViewModel
    {
        [Required]
        [EmailAddress]
        public String Email { get; set; }

        public Boolean Completed { get; set; }
    }
}
