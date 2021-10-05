using Authentication_System.Extensions;
using Authentication_System.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Authentication_System.Managers
{
    public class UsersManager : IUsersManager
    {
        protected int SALT_Lenght;

        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IDataProtector _protector;

        public UsersManager(
                                AppDbContext context,
                                IDataProtectionProvider dataProtectionProvider,
                                IConfiguration configuration
                           )
        {
            this._context = context;
            this._configuration = configuration;
            this._protector = dataProtectionProvider.CreateProtector(_configuration.GetValue<string>("Protection:Security"));
        }

        public AppUser AddNewUser(AppUser user, string providerName = null)
        {

            user.Password = PasswordHasher(user.Password);

            var entity = _context.AppUsers.Add(user);
            var result = _context.SaveChanges();

            if (result > 0 && !String.IsNullOrEmpty(providerName))
            {
                //user.Providers.Add(new Provider() { Name = providerName, User = user });
                //_context.Providers.Add(new Provider() { Name = providerName, User = user });
                AddUserProvider(entity.Entity, providerName);
            }

            return entity.Entity;
        }

        public bool AddUserProvider(AppUser user, string provider)
        {

            var existProvider = _context.Providers.Where(p => p.Name.Equals(provider))
                                        .Where(p => p.User.Username.Equals(user.Username))
                                        .FirstOrDefault();

            if (existProvider is not null)
            {
                return false;
            }

            _context.Providers.Add(new Provider() { Name = provider, User = user });
            var result = this._context.SaveChanges();

            return result > 0;
        }

        public bool HasProvider(AppUser user, string providerName)
        {
            return _context.Providers.Where(p => p.User.UserId == user.UserId)
                                      .Any(p => p.Name.Equals(providerName));
        }

        public AppUser GetAppUserByEmail(string email)
        {
            return _context.AppUsers.Where(u => u.Username == email)
                                    .Where(u => u.Email == email)
                                    .FirstOrDefault();
        }

        public AppUser GetAppUserById(string id)
        {
            return _context.AppUsers.Where(u => u.UserId.ToString() == id).FirstOrDefault();
        }

        public AppUser GetAppUserByPassword(string email, string password)
        {
            var user = _context.AppUsers.Where(u => u.Username == email).FirstOrDefault();
            if (user is not null)
            {
                var isValid = IsValidPasswordHash(password, user.Password);

                return isValid ? user : null;
            }

            return user;
        }

        public AppUser GetAppUserByProvider(string email, string providerName)
        {
            var t = GetAppUserByEmail(email).Providers.Any(p => p.Name.Equals(providerName));

            var user = _context.AppUsers.Where(u => u.Username == email)
                                        .Where(u => u.Providers.Any(p => p.Name.Equals(providerName)))
                                        .FirstOrDefault();
            return user;
        }

        public List<Claim> GetUserClaims(string email)
        {
            var appUser = GetAppUserByEmail(email);

            if (appUser is null)
            {
                return null;
            }
            else
            {
                List<Claim> claims = new();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, appUser.UserId.ToString()));
                claims.Add(new Claim(ClaimTypes.Name, appUser.Username));
                claims.Add(new Claim(ClaimTypes.Email, appUser.Email));
                claims.Add(new Claim(ClaimTypes.GivenName, appUser.Firstname));
                claims.Add(new Claim(ClaimTypes.Surname, appUser.Lastname));
                //claims.Add(new Claim(ClaimTypes.MobilePhone, appUser.MobilePhone));

                foreach (var role in appUser.RoleList)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                return claims;
            }
        }

        public List<Claim> GetClaims(AppUser appUser)
        {
            if (appUser is null)
            {
                return null;
            }

            List<Claim> claims = new();
            claims.Add(new Claim(ClaimTypes.NameIdentifier, appUser.UserId.ToString()));
            claims.Add(new Claim(ClaimTypes.Name, appUser.Username));
            claims.Add(new Claim(ClaimTypes.Email, appUser.Email));
            claims.Add(new Claim(ClaimTypes.GivenName, appUser.Firstname));
            claims.Add(new Claim(ClaimTypes.Surname, appUser.Lastname));
            //claims.Add(new Claim(ClaimTypes.MobilePhone, appUser.MobilePhone));

            foreach (var role in appUser.RoleList)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }

        //////////////////////////////////////// <Protected Methods> ////////////////////////////////////////////

        protected string PasswordHasher(string password)
        {
            byte[] saltBytes = GenerateSalt();
            string saltString = Convert.ToBase64String(saltBytes);

            string hashedPasswordString = HashPassword(saltBytes, password);

            var hash = $"{saltString}{hashedPasswordString}";

            return _protector.Protect(hash);
        }

        protected bool IsValidPasswordHash(string inputPassword, string password)
        {
            SALT_Lenght = Convert.ToBase64String(GenerateSalt()).Length;

            password = _protector.Unprotect(password);

            var salt = password.Substring(0, SALT_Lenght);

            var saltBytes = Convert.FromBase64String(salt);

            //var passwordBytes = GetBytes(inputPassword);

            var hashedPasswordString = HashPassword(saltBytes, inputPassword);

            var hash = $"{salt}{hashedPasswordString}";

            return hash == password;
        }

        protected byte[] GenerateSalt()
        {
            byte[] salt = new byte[128 / 8];

            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetNonZeroBytes(salt);
            }

            return salt;
        }

        protected string HashPassword(byte[] saltBytes, string passwordBytes)
        {

            var hashBytes = KeyDerivation.Pbkdf2(
                                                    password: passwordBytes,
                                                    salt: saltBytes,
                                                    prf: KeyDerivationPrf.HMACSHA256,
                                                    iterationCount: 100000,
                                                    numBytesRequested: 256 / 8
                                                );

            return Convert.ToBase64String(hashBytes);

            //using (var hashedPasswordBytes = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 10000))
            //{
            //    return Convert.ToBase64String(hashedPasswordBytes.GetBytes(24));
            //}
        }

        protected byte[] GetBytes(string password)
        {
            return Encoding.ASCII.GetBytes(password);
        }
    }
}
