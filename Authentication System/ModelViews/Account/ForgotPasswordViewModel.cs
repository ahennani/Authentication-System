using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class ForgotPasswordViewModel
    {
        [Display(Name = "Registered email address"), Required, EmailAddress]
        public string Email { get; set; }
        public bool IsSuccess { get; set; }
    }
}
