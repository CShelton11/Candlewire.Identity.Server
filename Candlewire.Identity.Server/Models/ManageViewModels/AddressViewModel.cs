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

        [Required]
        [Display(Name = "Street Address")]
        public String Street { get; set; }

        [Required]
        [Display(Name = "City")]
        public String City { get; set; }

        [Required]
        [Display(Name = "State")]
        public String State { get; set; }

        [Required]
        [Display(Name = "Zip Code")]
        public String Zip { get; set; }


        public Object ToSerializable()
        {
            return new
            {
                Street = this.Street,
                City = this.City,
                State = this.State,
                Zip = this.Zip
            };
        }
    }
}
