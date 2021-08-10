using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.HomeViewModels
{
    public class ClientViewModel
    {
        public String ClientName { get; set; }
        public String ClientDescription { get; set; }
        public String ClientUri { get; set; }
        public String ClientImage { get; set; }
    }
}
