using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class ConfirmEmailViewModel
    {
        public string Email { get; set; }
        public bool IsSuccess { get; set; }
        public bool IsConfirmed { get; set; }
    }
}
