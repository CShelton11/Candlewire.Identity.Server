using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Settings
{
    public class AuthSettings
    {
        public String ClientId { get; set; }
        public String ClientSecret { get; set; }
        public String CallbackPath { get; set; }
    }
}
