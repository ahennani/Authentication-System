using Authentication_System.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication_System.Models
{
    public class ManageUsers
    {
        private readonly AppDbContext _context;

        public ManageUsers(AppDbContext context)
        {
            this._context = context;
        }

        public bool GetUser(string username, out List<Claim> claims)
        {
            claims = new List<Claim>();
            var appUser = _context.AppUsers
                .Where(a => a.Username == username)
                .FirstOrDefault();

            if (appUser is null)
            {
                return false;
            }
            else
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, username));
                claims.Add(new Claim(ClaimTypes.Name, username));
                claims.Add(new Claim(ClaimTypes.GivenName, appUser.Firstname));
                claims.Add(new Claim(ClaimTypes.Surname, appUser.Lastname));
                claims.Add(new Claim(ClaimTypes.Email, appUser.Username));
                //claims.Add(new Claim(ClaimTypes.MobilePhone, appUser.Mobile));

                foreach (var role in appUser.RoleList)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
                return true;
            }
        }

        public void GetUserClaims(string username, out List<Claim> claims)
        {
            claims = new List<Claim>();

            var appUser = _context.AppUsers
                .Where(a => a.Username == username)
                .FirstOrDefault();

            claims.Add(new Claim(ClaimTypes.NameIdentifier, username));
            claims.Add(new Claim(ClaimTypes.Name, username));
            claims.Add(new Claim(ClaimTypes.GivenName, appUser.Firstname));
            claims.Add(new Claim(ClaimTypes.Surname, appUser.Lastname));
            claims.Add(new Claim(ClaimTypes.Email, appUser.Username));
            //claims.Add(new Claim(ClaimTypes.MobilePhone, appUser.Mobile));

            foreach (var role in appUser.RoleList)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }

        public AppUser AddNewUser(string providerName, List<Claim> claims)
        {
            var appUser = new AppUser()
            {
                Username = claims.GetClaim(ClaimTypes.Email),
                Email = claims.GetClaim(ClaimTypes.Email),
                Firstname = claims.GetClaim(ClaimTypes.GivenName),
                Lastname = claims.GetClaim(ClaimTypes.Surname),
                Roles = "User"
            };
            appUser.Providers.Add(new Provider() { Name = providerName, User = appUser });

            var entity = _context.AppUsers.Add(appUser);
            _context.SaveChanges();

            return entity.Entity;
        }

        public AppUser AddProviderToUser(AppUser user, string provider)
        {
            //user.Providers.Add(new Provider() { Name = provider, User = user});
            //var entity = _context.Update<AppUser>(user);
            //this._context.SaveChanges();

            this._context.Providers.Add(new Provider() { Name = provider, User = user });
            var result = this._context.SaveChanges();


            return user;
        }

        // Find User With External Provider
        public AppUser FindAppUser(string email)
        {
            return _context.AppUsers.Where(u => u.Username == email)
                                    .Where(u => u.Email == email)
                                    .FirstOrDefault();
        }

        // Find User With Password
        public AppUser FindAppUserByPassword(string email, string providerName, string password = null)
        {
            return _context.AppUsers.Where(u => u.Username == email)
                                    .Where(u => u.Email == email)
                                    .Where(u => u.Password == password)
                                    .FirstOrDefault();
        }

        public string PasswordHashing(string password)
        {
            using (var hash = new System.Security.Cryptography.HMACSHA512())
            {
                var passwordHash = hash.ComputeHash(Encoding.UTF8.GetBytes(password));
                var passwordSalt = hash.Key;

            }

            return null;
        }
    }
}
