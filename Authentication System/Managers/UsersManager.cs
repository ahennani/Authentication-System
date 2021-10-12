using Authentication_System.Data;
using Authentication_System.Enums;
using Authentication_System.Models;
using Authentication_System.Models.Account;
using Authentication_System.ModelViews.Account;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
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
        private readonly ILogger<UsersManager> _logger;
        private readonly IDataProtector _protector;

        public UsersManager(
                                AppDbContext context,
                                IDataProtectionProvider dataProtectionProvider,
                                IConfiguration configuration,
                                ILogger<UsersManager> logger
                           )
        {
            this._context = context;
            this._configuration = configuration;
            this._logger = logger;
            this._protector = dataProtectionProvider.CreateProtector(_configuration.GetValue<string>("Protection:Security"));
        }

        public Task<AppUser> AddNewUserAsync(AppUser user, string providerName = null)
        {
            return Task.Run(() =>
            {
                user.SecurityStamp = Guid.NewGuid();
                user.Password = PasswordHasher(user.Password);

                var entity = _context.AppUsers.Add(user);
                var result = _context.SaveChanges();

                if (result > 0 && !String.IsNullOrEmpty(providerName))
                {
                    AddUserProvider(entity.Entity, providerName);
                }

                return entity.Entity;
            });
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

        public bool ChangePasswordAsync(AppUser currentUser, string currentPasword, string newPassword)
        {
            var user = _context.AppUsers.Find(currentUser.UserId);

            var isMatched = IsValidPasswordHash(currentPasword, user.Password);
            if (isMatched)
            {
                var hashedNewPaswword = PasswordHasher(newPassword);
                user.Password = hashedNewPaswword;

                return _context.SaveChanges() > 0;
            }

            return false;
        }

        public async Task<string> GeneratePasswordResetTokenAsync(AppUser user)
        {
            return await GenerateAsync(user, TokenPurpuse.ForgetPassword);
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(AppUser user)
        {
            return await GenerateAsync(user, TokenPurpuse.EmailConfirmation);
        }

        public async Task<ResultViewModel> ResetPasswordAsync(AppUser user, string token, string newPassword)
        {
            var result = new ResultViewModel();

            var validateToken = await ValidateAsync(user, TokenPurpuse.ForgetPassword, token);
            if (!validateToken.Validated)
            {
                result.Errors.Add("Invalid Email Confirmation Link !!");
                return result;
            }

            var isChanged = ChangeForgottenPasswordAsync(user, newPassword);
            if (!isChanged)
            {
                result.Errors.Add("Password Did Not Change !!");
            }

            return result;
        }

        public async Task<ResultViewModel> ConfirmEmailAsync(AppUser user, string token)
        {
            var result = new ResultViewModel();

            var validateToken = await ValidateAsync(user, TokenPurpuse.EmailConfirmation, token);
            if (!validateToken.Validated)
            {
                result.Errors.Add("Invalid Email Confirmation Link !!");
            }

            if (user.EmailConfirmed is true)
            {
                result.Errors.Add("Confirmation Link Is Not Valid !!");
                return result;
            }

            await Task.Run(() =>
            {
                user.EmailConfirmed = true;
                _context.Attach(user);
                _context.Entry(user).Property(p => p.EmailConfirmed).IsModified = true;
                _context.SaveChanges();
            });

            return result;
        }

        //////////////////////////////////////// <Protected Methods> ////////////////////////////////////////////

        protected Task<string> GenerateAsync(AppUser user, TokenPurpuse purpuse)
        {
            return Task.Run(() =>
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    var ttt = TokenPurpuse.EmailConfirmation.ToString();
                    StreamWriter writer = new StreamWriter(ms);
                    writer.WriteLine(user.UserId.ToString());
                    writer.WriteLine(user.SecurityStamp);
                    writer.WriteLine(purpuse.ToString());
                    writer.WriteLine(DateTime.UtcNow);
                    writer.Flush();

                    //var res = Convert.ToBase64String(ms.ToArray());
                    //var protectedRes = _protector.Protect(res);
                    //_logger.LogError($"\n\nGenerateAsync:\n\t => {res}\n\t => {protectedRes}\n\n");
                    //return protectedRes;

                    return _protector.Protect(Convert.ToBase64String(ms.ToArray()));
                }
            });
        }
        
        protected Task<TokenValidationModel> ValidateAsync(AppUser user, TokenPurpuse tokenPurpuse, string token)
        {
            var result = new TokenValidationModel();

            var data = Convert.FromBase64String(_protector.Unprotect(token));

            //_logger.LogError($"\n\nValidateAsync:\n\t => {token}\n\t => {_protector.Unprotect(token)}\n\n");

            return Task.Run(() =>
            {
                using (MemoryStream ms = new MemoryStream(data))
                {
                    var reader = new StreamReader(ms);
                    var userId = reader.ReadLine();
                    var securityStamp = new Guid(reader.ReadLine());
                    var purpuse = reader.ReadLine();
                    var when = DateTime.Parse(reader.ReadLine());

                    if (when < DateTime.UtcNow.AddHours(-24))
                    {
                        result.Errors.Add(TokenValidationStatus.Expired);
                    }

                    if (securityStamp != user.SecurityStamp)
                    {
                        result.Errors.Add(TokenValidationStatus.SecurityStamp);
                    }

                    if (purpuse != tokenPurpuse.ToString())
                    {
                        result.Errors.Add(TokenValidationStatus.WrongPurpose);
                    }

                    if (user.UserId.ToString() != userId)
                    {
                        result.Errors.Add(TokenValidationStatus.WrongUser);
                    }

                    return result;
                }
            });
        }

        protected bool ChangeForgottenPasswordAsync(AppUser user, string newPassword)
        {
            user.Password = PasswordHasher(newPassword);

            var r1 = _context.Attach(user);
            _context.Entry(user).Property(u => u.Password).IsModified = true;
            
            return _context.SaveChanges() > 0;
        }

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
        }

        protected byte[] GetBytes(string password)
        {
            return Encoding.ASCII.GetBytes(password);
        }
    
    
    }
}
