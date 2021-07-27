using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Contexts
{
    public class ProtectionDbContext: DbContext, IDataProtectionKeyContext
    {
        public ProtectionDbContext(DbContextOptions<ProtectionDbContext> options) : base(options)
        {
            
        }

        public DbSet<DataProtectionKey> DataProtectionKeys { get; set; }
    }
}
