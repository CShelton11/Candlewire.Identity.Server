using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class ProfileViewModel : BaseViewModel
    {
        [Required]
        [Display(Name = "First Name")]
        public String FirstName { get; set; }

        [Required]
        [Display(Name = "Last Name")]
        public String LastName { get; set; }

        [Display(Name = "Username")]
        public String Username { get; set; }

        [Display(Name = "Nickname")]
        public String Nickname { get; set; }

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

        [Required(ErrorMessage = "Date of birth is required")]
        [Display(Name = "Date Of Birth")]
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }

        public AddressViewModel BillingAddress { get; set; }
        public AddressViewModel ShippingAddress { get; set; }
        public String EditableClaims { get; set; }
    }
}
