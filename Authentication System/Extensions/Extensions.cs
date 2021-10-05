using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System.Extensions
{
    public static class Extensions
    {
        public static string GetClaim(this List<Claim> claims, string name)
        {
            foreach (var item in claims)
            {
                var type = item.Type;
                var val = item.Value;
            }
            return claims.FirstOrDefault(c => c.Type == name).Value;
        }
    }
}
