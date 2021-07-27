using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.ComponentModel.DataAnnotations;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class PasswordViewModel: BaseViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public String OldPassword { get; set; }

        [Required]
        [RegularExpression("^((?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])|(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[^a-zA-Z0-9])|(?=.*?[A-Z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])|(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9])).{9,}$", ErrorMessage = "Passwords must be at least 9 characters and contain at 3 of 4 of the following: upper case (A-Z), lower case (a-z), number (0-9) and special character (e.g. !@#$%^&*)")]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public String NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public String ConfirmPassword { get; set; }

        public String StatusMessage { get; set; }
    }
}
