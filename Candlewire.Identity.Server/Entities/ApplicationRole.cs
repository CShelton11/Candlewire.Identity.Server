using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Entities
{
    public class ApplicationRole: IdentityRole
    {
        public virtual List<ApplicationRoleMap> RoleMaps { get; set; }
        public virtual List<ApplicationRoleClient> RoleClients { get; set; }
    }
}
