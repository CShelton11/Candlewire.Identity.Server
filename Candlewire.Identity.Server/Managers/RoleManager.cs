using Candlewire.Identity.Server.Contexts;
using Candlewire.Identity.Server.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    public class RoleManager
    {
        private readonly ApplicationDbContext _context;

        public RoleManager(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<List<ApplicationRoleMap>> GetRoleMaps()
        {
            var query = from a in _context.RoleMaps
                        join b in _context.Roles on a.RoleId equals b.Id
                        select a;
            return await query.ToListAsync();
        }

        public async Task<List<ApplicationRole>> GetRoles(String providerName, String domainName, List<String> domainRoles)
        {
            var query = from a in _context.RoleMaps
                        join b in _context.Roles on a.RoleId equals b.Id
                        where a.ProviderName.ToLower() == providerName.ToLower()
                        && a.DomainName.ToLower() == domainName.ToLower()
                        && domainRoles.Contains(a.DomainRole)
                        select b;
            return await query.Distinct().ToListAsync();
        }

        public async Task<List<ApplicationRoleClient>> GetRoleClients()
        {
            var query = from a in _context.RoleClients
                        join b in _context.Roles on a.RoleId equals b.Id
                        select a;
            return await query.ToListAsync();
        }

        public async Task<List<ApplicationRoleClient>> GetRoleClients(ApplicationUser user)
        {
            var id = user.Id;
            var query = from a in (from a in _context.UserRoles where a.UserId == id select new { a.RoleId })
                        join b in _context.RoleClients on a.RoleId equals b.RoleId
                        select b;
            return await query.Distinct().ToListAsync();
        }
    }
}
