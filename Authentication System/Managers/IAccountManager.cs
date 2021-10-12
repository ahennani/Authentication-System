using Authentication_System.Models;
using Authentication_System.ModelViews;
using Authentication_System.ModelViews.Account;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System.Managers
{
    public interface IAccountManager
    {
        Task<ResultViewModel> CreateAppUserAsync(SignupViewModel model);
        Task<ResultViewModel> CreateExternalAppUserAsync(string provider);
        bool AddAppUserProvider(AppUser user, string provider);
        Task<AppUser> GetAppUserByEmailAsync(string email);
        AppUser GetCurrentAppUser();
        AppUser GetExternalAppUser();
        List<Claim> GetExternalAppUserClaims();
        Task SignOutAsync();
        Task SignInAsync(AppUser user);
        bool IsAuthenticated();
        bool IsProviderExist(AppUser user, string providerName);
        Task<ResultViewModel> PasswordSignInAsync(LoginViewModel model);
        Task<List<AuthenticationScheme>> GetExternalProvidersAsync();
        AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string returnUrl);
        ValidateViewModel CheckPasswordValidation(string password);
        ResultViewModel ChangePasswordAsync(ChangePasswordViewModel model);
        Task<bool> SendConfirmationEmailTokenEmailAsync(AppUser user);
        Task<bool> SendForgotPasswordEmailAsync(string email);
        Task GenerateEmailConfirmationTokenAsync(AppUser user);
        Task GenerateForgotPasswordTokenAsync(AppUser user);
        Task<ResultViewModel> ResetPasswordAsync(ResetPasswordViewModel model);
        Task<ResultViewModel> ConfirmUserEmailAsync(string uid, string token, string email);
        Task<bool> EmailConfirmedAsync(string email);
        Task<bool> IsEmailExistAsync(string email);
    }
}
