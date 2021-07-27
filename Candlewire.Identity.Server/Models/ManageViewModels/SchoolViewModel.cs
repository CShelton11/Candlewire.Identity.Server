using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Models.ManageViewModels
{
    public class SchoolViewModel: BaseViewModel
    {
        public SchoolBaseModel School { get; set; } = new SchoolBaseModel();
        public List<SchoolBaseModel> Schools { get; set; } = new List<SchoolBaseModel>();
        public List<String> Errors { get; set; } = new List<String>();
        public String Editable { get; set; }
    }

    public class SchoolBaseModel
    {
        [Required(ErrorMessage = "Select a school from the suggestions list")]
        [Display(Name = "School Id")]
        public String SchoolId { get; set; }

        [Display(Name = "School Name")]
        public String SchoolName { get; set; }

        public String SchoolAction { get; set; }

        [Required(ErrorMessage = "Start is a required field")]
        [Display(Name = "Start")]
        public String StartDate { get; set; }

        [Required(ErrorMessage = "End is a required field")]
        [Display(Name = "End")]
        public String EndDate { get; set; }
    }
}
