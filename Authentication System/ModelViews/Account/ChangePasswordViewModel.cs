using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class ChangePasswordViewModel
    {
        [Required, DataType(DataType.Password), Display(Name = "Current password")]
        public string CurrentPassword { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "New password")]
        public string NewPassword { get; set; }

        [Required, DataType(DataType.Password), Display(Name = "Re new password")]
        //[Compare("NewPassword", ErrorMessage = "Confirm new password does not match")]
        public string ConfirmNewPassword { get; set; }

        public bool IsSuccess { get; set; }
    }
}
