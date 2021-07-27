using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Contexts
{
    public class PersistenceDbContext : DbContext
    {
        public PersistenceDbContext(DbContextOptions<PersistenceDbContext> options) : base(options)
        {
            
        }

        public DbSet<PersistenceItem> PersistenceItems { get; set; }
    }

    public class PersistenceItem
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Int64 PersistenceId { get; set; }
        public String PersistenceToken { get; set; }
        public String PersistenceKey { get; set; }
        public String PersistenceData { get; set; }
        public DateTime PersistenceExpiration { get; set; }
    }
}
