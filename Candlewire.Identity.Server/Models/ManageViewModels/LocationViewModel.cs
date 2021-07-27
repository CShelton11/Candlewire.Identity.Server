using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class LocationViewModel : BaseViewModel
    {
        public LocationBaseModel Location { get; set; } = new LocationBaseModel();
        public List<LocationBaseModel> Locations { get; set; } = new List<LocationBaseModel>();
        public List<String> Errors { get; set; } = new List<String>();
        public String Editable { get; set; }
    }

    public class LocationBaseModel
    {
        [Required(ErrorMessage = "Select a city from the suggestions list")]
        [Display(Name = "City Id")]
        public String CityId { get; set; }

        [Display(Name = "City Name")]
        public String CityName { get; set; }

        public String CityAction { get; set; }

        [Required(ErrorMessage = "Start is a required field")]
        [Display(Name = "Start")]
        public String StartDate { get; set; }

        [Required(ErrorMessage = "End is a required field")]
        [Display(Name = "End")]
        public String EndDate { get; set; }
    }
}
