using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.RegisterViewModels
{
    public class TermsViewModel: BaseViewModel
    {
        public String TermsHtml { get; set; }
        public String TermsEmail { get; set; }
        public String ReturnUrl { get; set; }
    }
}
