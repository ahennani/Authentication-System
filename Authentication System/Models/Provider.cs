using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Models
{
    public class Provider
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ProviderId { get; set; }

        public string Name { get; set; }

        public AppUser User { get; set; }
    }
}
