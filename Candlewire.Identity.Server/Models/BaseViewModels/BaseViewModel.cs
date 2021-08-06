using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.BaseViewModels
{
    public class BaseViewModel
    {
        [Newtonsoft.Json.JsonIgnore]
        [System.Text.Json.Serialization.JsonIgnore]
        public String ToastTitle { get; set; } = "";

        [Newtonsoft.Json.JsonIgnore]
        [System.Text.Json.Serialization.JsonIgnore]
        public List<String> ToastMessages { get; set; } = new List<String>();

        [Newtonsoft.Json.JsonIgnore]
        [System.Text.Json.Serialization.JsonIgnore]
        public String ToastLevel { get; set; } = "";
    }
}
