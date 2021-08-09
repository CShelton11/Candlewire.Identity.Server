using Candlewire.Identity.Server.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace Candlewire.Identity.Server.Contexts
{
    public class ApplicationDbContext: IdentityDbContext<ApplicationUser, ApplicationRole, String>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options): base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<ApplicationRoleMap>()
                .HasOne(a => a.Role)
                .WithMany(b => b.RoleMaps)
                .HasForeignKey(e => e.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<ApplicationRoleClient>()
                .HasOne(a => a.Role)
                .WithMany(b => b.RoleClients)
                .HasForeignKey(e => e.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            base.OnModelCreating(builder);
        }

        public virtual DbSet<ApplicationRoleMap> RoleMaps { get; set; }
        public virtual DbSet<ApplicationRoleClient> RoleClients { get; set; }
    }
}
