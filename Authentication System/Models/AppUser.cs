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
            //Roles = String.Join(",", RoleList);
        }

        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string MobilePhone { get; set; }
        public string Roles { get; set; }
        public Guid SecurityStamp { get; set; }
        public bool EmailConfirmed { get; set; }

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
