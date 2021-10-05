using Authentication_System.Extensions;
using Authentication_System.Models;
using Authentication_System.ModelViews;
using Authentication_System.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System.Managers
{
    public class AccountManager : IAccountManager
    {
        private readonly AppDbContext _context;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly IUsersManager _manageUsers;
        private readonly ValidatePassword _validatePassword;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;
        private readonly IDataProtector _protector;

        public AccountManager(
                                    AppDbContext context,
                                    IAuthenticationSchemeProvider authenticationSchemeProvider,
                                    IUsersManager manageUsers,
                                    ValidatePassword validatePassword,
                                    IDataProtectionProvider dataProtectionProvider,
                                    IHttpContextAccessor httpContextAccessor,
                                    IConfiguration configuration
                             )
        {
            this._context = context;
            this._authenticationSchemeProvider = authenticationSchemeProvider;
            this._manageUsers = manageUsers;
            this._validatePassword = validatePassword;
            this._httpContextAccessor = httpContextAccessor;
            this._configuration = configuration;
            this._protector = dataProtectionProvider.CreateProtector(_configuration.GetValue<string>("Protection:Security"));
        }

        public async Task<ResultViewModel> CreateAppUserAsync(AccountSignupViewModel model)
        {
            var result = new ResultViewModel();

            var user = GetAppUserByEmail(model.Email);
            if (user is not null)
            {
                result.Errors.Add("There is Alredy a User With this Email !!..");
                return result;
            }

            user = new AppUser()
            {
                Username = model.Email,
                Firstname = model.FirstName,
                Lastname = model.LastName,
                Email = model.Email,
                Password = model.Password,
                Roles = "User"
            };

            var res = _manageUsers.AddNewUser(user);
            if (res is null)
            {
                result.Errors.Add("The Signing up failed !!");
                return result;
            }

            await SignInAsync(user);

            return result;
        }

        public async Task<ResultViewModel> CreateExternalAppUserAsync(string provider)
        {
            ResultViewModel result = null;

            var claims = GetExternalAppUserClaims();

            var user = new AppUser()
            {
                Username = claims.GetClaim(ClaimTypes.Email),
                Email = claims.GetClaim(ClaimTypes.Email),
                Firstname = claims.GetClaim(ClaimTypes.GivenName),
                Lastname = claims.GetClaim(ClaimTypes.Surname),
                Roles = "User"
            };


            var createdUser = _manageUsers.AddNewUser(user, provider);
            if (createdUser is null)
            {
                result.Errors.Add("There is Alredy a User With this Email !!..");
                return result;
            }

            await SignInAsync(user);

            return result;
        }

        public bool AddAppUserProvider(AppUser user, string provider)
        {
            return _manageUsers.AddUserProvider(user, provider);
        }

        public async Task<ResultViewModel> PasswordSignInAsync(AccountLoginViewModel model)
        {
            var user = _manageUsers.GetAppUserByPassword(model.Email, model.Password);
            ResultViewModel result = null;
            if (user is null)
            {
                result = new();
                result.Errors.Add("The password Or Email Is Not Correct !!");
            }

            await SignInAsync(user);

            return result;
        }

        public async Task SignInAsync(AppUser user)
        {
            var claims = _manageUsers.GetClaims(user);

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            await _httpContextAccessor.HttpContext.SignInAsync(claimsPrincipal);
        }

        public async Task SignOutAsync()
        {
            await _httpContextAccessor.HttpContext.SignOutAsync();
        }

        public bool IsAuthenticated()
        {
            return _httpContextAccessor.HttpContext.User.Identity.IsAuthenticated;
        }

        public bool IsProviderExist(AppUser user, string providerName)
        {
            return _manageUsers.HasProvider(user, providerName);
        }

        public AppUser GetCurrentAppUser()
        {
            var userId = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = GetAppUserById(userId);
            return user;
        }

        public AppUser GetAppUserByEmail(string email)
        {
            return _manageUsers.GetAppUserByEmail(email);
        }

        public AppUser GetAppUserById(string id)
        {
            return _manageUsers.GetAppUserById(id);
        }

        public AppUser GetExternalAppUser()
        {
            var email = _httpContextAccessor.HttpContext.User.Claims.ToList().GetClaim(ClaimTypes.Email);
            
            return _manageUsers.GetAppUserByEmail(email);
        }

        public AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string redirectUri)
        {
            var authenticationProperties = new AuthenticationProperties() { RedirectUri = redirectUri };
            authenticationProperties.SetParameter("prompt", "select_account");

            return authenticationProperties;
        }
        public List<Claim> GetExternalAppUserClaims()
        {
            return _httpContextAccessor.HttpContext.User.Claims.ToList();
        }

        public ValidateViewModel CheckPasswordValidation(string password)
        {
            return new ValidateViewModel()
                       {
                           IsValid = _validatePassword.IsValidate(password, out List<string> errors),
                           Errors = errors
                       };
        }

        public async Task<List<AuthenticationScheme>> GetExternalProviders()
        {
            return (await this._authenticationSchemeProvider.GetAllSchemesAsync())
                                .Where(p => !p.Name.Equals("Cookies"))
                                .ToList();
        }
    }
}
