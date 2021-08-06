using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class AddressViewModel : BaseViewModel
    {
        [Required]
        public String Type { get; set; }

        [Display(Name = "Street Address")]
        public String Street { get; set; }

        [Display(Name = "City")]
        public String City { get; set; }

        [Display(Name = "State")]
        public String State { get; set; }

        [Display(Name = "Zip Code")]
        public String Zip { get; set; }
    }
}
