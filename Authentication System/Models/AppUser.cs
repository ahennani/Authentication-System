using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Models
{
    public class AppUser
    {
        public AppUser()
        {
            Providers = new List<Provider>();
        }

        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        // [Required]
        public string Email { get; set; }
        public string Password { get; set; }
        public string Mobile { get; set; }
        public string Roles { get; set; }

        // [Required]
        public ICollection<Provider> Providers { get; set; }

        public List<string> RoleList
        {
            get
            {
                return Roles?.Split(',').ToList() ?? new List<string>();
            }
        }
    }
}
