using Candlewire.Identity.Server.Contexts;
using IdentityServer4.EntityFramework.DbContexts;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Migrations
{
    public class DatabaseMigrator
    {
        public void MigrateDatabase(IApplicationBuilder app)
        {
            using (var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context1 = scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>();
                context1.Database.Migrate();

                var context2 = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context2.Database.Migrate();

                var context3 = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                context3.Database.Migrate();

                var context4 = scope.ServiceProvider.GetRequiredService<PersistenceDbContext>();
                context4.Database.Migrate();

                var context5 = scope.ServiceProvider.GetRequiredService<ProtectionDbContext>();
                context5.Database.Migrate();
            }
        }
    }
}
