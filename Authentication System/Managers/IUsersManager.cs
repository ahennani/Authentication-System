using Authentication_System.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System.Managers
{
    public interface IUsersManager
    {
        public AppUser AddNewUser(AppUser user, string providerName = null);
        public bool AddUserProvider(AppUser user, string provider);
        bool HasProvider(AppUser user, string providerName);
        public AppUser GetAppUserByEmail(string email);
        public AppUser GetAppUserById(string id);
        public AppUser GetAppUserByPassword(string email, string password);
        public AppUser GetAppUserByProvider(string email, string providerName);
        public List<Claim> GetUserClaims(string email);
        public List<Claim> GetClaims(AppUser user);
    }
}
