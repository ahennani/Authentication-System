using Authentication_System.Utilities;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class SignupViewModel
    {
        // [Required(ErrorMessage = "Password Should Not Be Empty")]
        [Display(Name = "FirstName")]
        public string FirstName { get; set; }

        // [Required(ErrorMessage = "Password Should Not Be Empty")]
        [Display(Name = "LastName")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Email Should Not Be Empty")]
        [DataType(DataType.EmailAddress)]
        [Display(Name = "Address Email")]
        [Remote(action: "VerifyEmail", controller: "Account")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password Should Not Be Empty")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [Remote(action:"IsValidePassword", controller:"Account")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password Most Match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; }

        public ExternalLoginsViewModel ExternalLogins { get; set; }
    }
}
