using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Web.Models {
    public class ApplicationUser : IdentityUser {

        [Display(Name = "Full Name")]
        [Required]
        [StringLength(100, MinimumLength = 3)]
        public string FullName { get; set; }

    }
}