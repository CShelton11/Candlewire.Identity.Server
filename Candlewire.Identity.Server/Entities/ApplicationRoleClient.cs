using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Entities
{
    [Table("AspNetRoleClients")]
    public class ApplicationRoleClient
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Int32 Id { get; set; }


        [ForeignKey("Role")]
        [StringLength(450)]
        public String RoleId { get; set; }

        public Int32 ClientId { get; set; }

        public virtual ApplicationRole Role { get; set; }
    }
}
