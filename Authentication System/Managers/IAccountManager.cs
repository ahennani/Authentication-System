using Authentication_System.Models;
using Authentication_System.ModelViews;
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
        Task<ResultViewModel> CreateAppUserAsync(AccountSignupViewModel model);
        Task<ResultViewModel> CreateExternalAppUserAsync(string provider);
        bool AddAppUserProvider(AppUser user, string provider);
        AppUser GetAppUserByEmail(string email);
        AppUser GetAppUserById(string id);
        AppUser GetCurrentAppUser();
        AppUser GetExternalAppUser();
        List<Claim> GetExternalAppUserClaims();
        Task SignOutAsync();
        Task SignInAsync(AppUser user);
        bool IsAuthenticated();
        bool IsProviderExist(AppUser user, string providerName);
        Task<ResultViewModel> PasswordSignInAsync(AccountLoginViewModel model);
        Task<List<AuthenticationScheme>> GetExternalProviders();
        AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string returnUrl);
        ValidateViewModel CheckPasswordValidation(string password);
    }
}
