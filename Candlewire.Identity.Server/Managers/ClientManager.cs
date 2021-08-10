using Candlewire.Identity.Server.Contexts;
using Candlewire.Identity.Server.Entities;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    public class ClientManager
    {
        private readonly ApplicationDbContext _applicationContext;
        private readonly ConfigurationDbContext _configurationContext;

        public ClientManager(ApplicationDbContext applicationContext, ConfigurationDbContext configurationContext)
        {
            _applicationContext = applicationContext;
            _configurationContext = configurationContext;
        }

        public async Task<List<Client>> GetClients(ApplicationUser user, List<String> roles)
        {
            var ids = await GetClientIds(user, roles);
            var query = from a in _configurationContext.Clients
                        where ids.Contains(a.Id)
                        select a;
            return (await query.ToListAsync());
        }

        private async Task<List<Int32>> GetClientIds(ApplicationUser user, List<String> roles)
        {
            var id = user.Id;
            var query = from a in _applicationContext.Roles
                        join b in _applicationContext.UserRoles on a.Id equals b.RoleId
                        join c in _applicationContext.RoleClients on b.RoleId equals c.RoleId
                        where roles.Contains(a.Name) && b.UserId == id
                        select new { c.ClientId };
            return (await query.ToListAsync()).Select(a => a.ClientId).ToList();
        }
    }
}
