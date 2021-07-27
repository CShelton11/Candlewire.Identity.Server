using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Settings
{
    public class EmailSettings
    {
        public String Provider { get; set; }
        public String From { get; set; }
        public String Token { get; set; }
    }
}
