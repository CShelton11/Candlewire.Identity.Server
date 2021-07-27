using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Candlewire.Identity.Server.Models.BaseViewModels;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Candlewire.Identity.Server.Models.AccountViewModels
{
    public class SendViewModel: BaseViewModel
    {
        public String SelectedProvider { get; set; }

        public List<String> AvailableProviders { get; set; } = new List<String>();

        public String ReturnUrl { get; set; }

        public Boolean RememberMe { get; set; }
    }
}
