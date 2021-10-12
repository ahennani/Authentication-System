using Authentication_System.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Models.Account
{
    public class TokenValidationModel
    {
        public bool Validated { get { return Errors.Count == 0; } }
        public readonly List<TokenValidationStatus> Errors = new List<TokenValidationStatus>();
    }
}
