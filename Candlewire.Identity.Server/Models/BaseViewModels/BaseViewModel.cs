using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.BaseViewModels
{
    public class BaseViewModel
    {
        // Toast on page load
        public String ToastTitle { get; set; } = "";
        public List<String> ToastMessages { get; set; } = new List<String>();
        public String ToastLevel { get; set; } = "";
    }
}
