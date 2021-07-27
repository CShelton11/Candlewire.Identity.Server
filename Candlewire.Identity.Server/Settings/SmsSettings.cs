using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Settings
{
    public class SmsSettings
    {
        public String Provider { get; set; }
        public String Sid { get; set; }
        public String Token { get; set; }
        public String From { get; set; }
    }
}
