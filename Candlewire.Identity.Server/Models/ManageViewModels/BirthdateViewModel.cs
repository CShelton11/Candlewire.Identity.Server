using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class BirthdateViewModel: BaseViewModel
    {
        [Display(Name = "Date Of Birth")]
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }
    }
}