using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class ResetPasswordViewModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Token { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "New password")]
        [Remote(action: "IsValidePassword", controller: "Account")]
        public string Password { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "Re enter new password")]
        [Compare("Password", ErrorMessage = "Confirm password does not match")]
        public string ConfirmPassword { get; set; }

        public bool IsSuccess { get; set; }
    }
}
