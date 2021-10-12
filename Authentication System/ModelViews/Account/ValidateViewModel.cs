using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class ValidateViewModel
    {
        public ValidateViewModel()
        {
            Errors = new();
        }
        public bool IsValid { get; set; }

        public List<string> Errors { get; set; }
    }
}
