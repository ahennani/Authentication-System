using Authentication_System.Extensions;
using Authentication_System.Data;
using Authentication_System.Models;
using Authentication_System.ModelViews.Account;
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
using Authentication_System.Services;
using Authentication_System.Models.Email;
using System.IO;
using Microsoft.Extensions.Logging;

namespace Authentication_System.Managers
{
    public class AccountManager : IAccountManager
    {
        private readonly AppDbContext _context;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly IUsersManager _manageUsers;
        private readonly ValidatePassword _validatePassword;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AccountManager> _logger;
        private readonly IDataProtector _protector;

        public AccountManager(
                                    AppDbContext context,
                                    IAuthenticationSchemeProvider authenticationSchemeProvider,
                                    IUsersManager manageUsers,
                                    ValidatePassword validatePassword,
                                    IDataProtectionProvider dataProtectionProvider,
                                    IHttpContextAccessor httpContextAccessor,
                                    IEmailService emailService,
                                    IConfiguration configuration,
                                    ILogger<AccountManager> logger
                             )
        {
            this._context = context;
            this._authenticationSchemeProvider = authenticationSchemeProvider;
            this._manageUsers = manageUsers;
            this._validatePassword = validatePassword;
            this._httpContextAccessor = httpContextAccessor;
            this._emailService = emailService;
            this._configuration = configuration;
            this._logger = logger;
            this._protector = dataProtectionProvider.CreateProtector(_configuration.GetValue<string>("Protection:Security"));
        }

        public async Task<ResultViewModel> CreateAppUserAsync(SignupViewModel model)
        {
            var result = new ResultViewModel();

            var user = await GetAppUserByEmailAsync(model.Email);
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

            var res = await _manageUsers.AddNewUserAsync(user);
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


            var createdUser = await _manageUsers.AddNewUserAsync(user, provider);
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

        public async Task<ResultViewModel> PasswordSignInAsync(LoginViewModel model)
        {
            var result = new ResultViewModel();

            var user = _manageUsers.GetAppUserByPassword(model.Email, model.Password);
            if (user is null)
            {
                result.Errors.Add("The password Or Email Is Not Correct !!");
                return result;
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
            var user = _manageUsers.GetAppUserById(userId);

            return user;
        }

        public Task<AppUser> GetAppUserByEmailAsync(string email)
        {
            return Task.FromResult(_manageUsers.GetAppUserByEmail(email));
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

        public async Task<List<AuthenticationScheme>> GetExternalProvidersAsync()
        {
            return (await this._authenticationSchemeProvider.GetAllSchemesAsync())
                                .Where(p => !p.Name.Equals("Cookies"))
                                .ToList();
        }

        public ResultViewModel ChangePasswordAsync(ChangePasswordViewModel model)
        {
            ResultViewModel result = new();
            var user = GetCurrentAppUser();

            var isChanged = _manageUsers.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!isChanged)
            {
                result.Errors.Add("Your Password May Not Be Correct !!");
            }

            return result;
        }

        public async Task GenerateEmailConfirmationTokenAsync(AppUser user)
        {
            await Task.CompletedTask;
        }

        public async Task GenerateForgotPasswordTokenAsync(AppUser user)
        {
            var token = await _manageUsers.GeneratePasswordResetTokenAsync(user);
            if (!string.IsNullOrEmpty(token))
            {
                await SendForgotPasswordEmailToUserAsync(user, token);
            }
        }

        public async Task<bool> SendForgotPasswordEmailAsync(string email)
        {
            var user = await GetAppUserByEmailAsync(email); //
            if (user is not null)
            {
                var token = await _manageUsers.GeneratePasswordResetTokenAsync(user);
                if (!string.IsNullOrEmpty(token))
                {
                    await SendForgotPasswordEmailToUserAsync(user, token);
                    return true;
                }
            }

            return false;
        }

        public async Task<bool> SendConfirmationEmailTokenEmailAsync(AppUser user)
        {
            if (user is not null)
            {
                var token = await _manageUsers.GenerateEmailConfirmationTokenAsync(user);
                if (!string.IsNullOrEmpty(token))
                {
                    await SendConfirmationEmailLinkToUserAsync(user, token);
                    return true;
                }
            }

            return false;
        }

        public async Task<ResultViewModel> ResetPasswordAsync(ResetPasswordViewModel model)
        {
            var user = _manageUsers.GetAppUserById(_protector.Unprotect(model.UserId.ToString()));

            return await _manageUsers.ResetPasswordAsync(user, model.Token, model.Password);
        }

        public async Task<ResultViewModel> ConfirmUserEmailAsync(string uid, string token, string email)
        {
            var user = _manageUsers.GetAppUserById(_protector.Unprotect(uid));
            if (user.Username != email)
            {
                var result = new ResultViewModel();
                result.Errors.Add("Confirmation Link For Wrog User !!");
                return result;
            }

            return await _manageUsers.ConfirmEmailAsync(user, token);
        }

        public async Task<bool> EmailConfirmedAsync(string email)
        {
            return (await GetAppUserByEmailAsync(email)).EmailConfirmed;
        }

        public async Task<bool> IsEmailExistAsync(string email)
        {
            var user = await GetAppUserByEmailAsync(email);

            return user is null;
        }


        #region Private methods

        private async Task SendForgotPasswordEmailToUserAsync(AppUser user, string token)
        {
            var appDomain = _configuration.GetSection("ApplicationContent").GetSection("AppDomain").Value;
            var resetPasswordLink = _configuration.GetSection("ApplicationContent").GetSection("ResetPasswordLink").Value;
            var path = Path.Combine(appDomain, resetPasswordLink);
            var link = string.Format(path, token, _protector.Protect(user.UserId.ToString()));

            _logger.LogError($"\n\nSendForgotPasswordEmailAsync:\n\t => {link}");

            UserEmailOptions userEmailOptions = new UserEmailOptions()
            {
                ToEmails = new List<string>() { user.Email },
                PlaceHolders = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("{{FirstName}}", user.Firstname),
                    new KeyValuePair<string, string>("{{Link}}", link)
                }
            };

            await Task.Run(async () =>
            {
                await _emailService.SendEmailForForgotPasswordAsync(userEmailOptions);
            });
        }

        private async Task SendConfirmationEmailLinkToUserAsync(AppUser user, string token)
        {
            var appDomain = _configuration.GetSection("ApplicationContent").GetSection("AppDomain").Value;
            var emailConfirmationLink = _configuration.GetSection("ApplicationContent").GetSection("ConfirmEmailLink").Value;
            var path = Path.Combine(appDomain, emailConfirmationLink);
            var link = string.Format(path, token, _protector.Protect(user.UserId.ToString()));
            link = $"{link}&email={user.Email}";

            _logger.LogError($"\n\nSendForgotPasswordEmailAsync:\n\t => {link}");

            UserEmailOptions userEmailOptions = new UserEmailOptions()
            {
                ToEmails = new List<string>() { user.Email },
                PlaceHolders = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("{{FirstName}}", user.Firstname),
                    new KeyValuePair<string, string>("{{Link}}", link)
                }
            };

            await Task.Run(async () =>
            {
                await _emailService.SendEmailForEmailConfirmationAsync(userEmailOptions);
            });
        }

        #endregion
    }
}
