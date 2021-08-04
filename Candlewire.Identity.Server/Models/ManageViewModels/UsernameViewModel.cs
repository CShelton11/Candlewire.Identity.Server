using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class UsernameViewModel: BaseViewModel
    {
        [Display(Name = "Username")]
        public String Username { get; set; }
    }
}
