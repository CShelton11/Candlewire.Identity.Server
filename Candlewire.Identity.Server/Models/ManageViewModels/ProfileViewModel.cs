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
        [Display(Name = "First Name")]
        public String FirstName { get; set; }

        [Display(Name = "Last Name")]
        public String LastName { get; set; }

        [Display(Name = "Username")]
        public String Username { get; set; }

        [Display(Name = "Nickname")]
        public String Nickname { get; set; }

        [Display(Name = "Email Address")]
        public String EmailAddress { get; set; }

        [Display(Name = "Email Confirmed")]
        public Boolean EmailConfirmed { get; set; }

        [Display(Name = "Phone Number")]
        public String PhoneNumber { get; set; }

        [Display(Name = "Phone Number Confirmed")]
        public Boolean PhoneConfirmed { get; set; }

        [Display(Name = "Date Of Birth")]
        public DateTime? Birthdate { get; set; }

        public AddressViewModel BillingAddress { get; set; }
        public AddressViewModel ShippingAddress { get; set; }
        public String EditableClaims { get; set; }
        public String VisibleClaims { get; set; }
    }
}
