using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Utilities
{
    public class ValidPasswordAttribute : ValidationAttribute
    {
        private readonly string password;

        public ValidPasswordAttribute(string password)
        {
            this.password = password;
        }

        public override bool IsValid(object value)
        {
            return base.IsValid(value); 
        }
    }
}
