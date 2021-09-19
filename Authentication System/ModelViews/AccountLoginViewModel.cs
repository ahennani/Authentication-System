using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews
{
    public class AccountLoginViewModel
    {
        [Required(ErrorMessage = "Email Should Not Be Empty")]
        [DataType(DataType.EmailAddress)]
        [Display(Name = "Address Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password Should Not Be Empty")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        public ExternalLoginsViewModel ExternalLogins { get; set; }

    }
}
