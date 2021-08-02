using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Entities
{
    [Table("AspNetRoleMaps")]
    public class ApplicationRoleMap
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Int32 Id { get; set; }

        [ForeignKey("Role")]
        [StringLength(450)]
        public String RoleId { get; set; }
        
        public String ProviderName { get; set; }
        
        public String DomainName { get; set; }
        
        public String DomainRole { get; set; }

        public virtual ApplicationRole Role { get; set; }
    }
}
