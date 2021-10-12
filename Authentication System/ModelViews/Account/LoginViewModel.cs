using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email Should Not Be Empty")]
        [DataType(DataType.EmailAddress)]
        [Display(Name = "Address Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password Should Not Be Empty")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [Remote(action: "IsValidePassword", controller: "Account")]
        public string Password { get; set; }

        public ExternalLoginsViewModel ExternalLogins { get; set; }

    }
}
