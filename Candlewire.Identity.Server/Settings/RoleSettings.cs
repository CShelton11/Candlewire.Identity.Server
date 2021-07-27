using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Settings
{
    public class RoleSettings
    {
        public List<RoleSetting> Data { get; set; }

        public Boolean HasRequirements(List<Claim> claims)
        {
            var requirements = Data;
            var matches = from a in claims.ToList() 
                          join b in requirements on a.Type equals b.RoleName 
                          select a;
            return matches.Count() == claims.Count();   
        }
    }

    public class RoleSetting
    {
        public String RoleName { get; set; }
        public Boolean RoleDefaulted { get; set; }
        public List<String> RequiredClaims { get; set; }
    }
}
