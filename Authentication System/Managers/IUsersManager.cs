using Authentication_System.Models;
using Authentication_System.ModelViews.Account;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System.Managers
{
    public interface IUsersManager
    {
        Task<AppUser> AddNewUserAsync(AppUser user, string providerName = null);
        bool AddUserProvider(AppUser user, string provider);
        bool HasProvider(AppUser user, string providerName);
        bool ChangePasswordAsync(AppUser user, string currentPasword, string newPassword);
        AppUser GetAppUserByEmail(string email);
        AppUser GetAppUserById(string id);
        AppUser GetAppUserByPassword(string email, string password);
        AppUser GetAppUserByProvider(string email, string providerName);
        List<Claim> GetUserClaims(string email);
        List<Claim> GetClaims(AppUser user);
        Task<string> GeneratePasswordResetTokenAsync(AppUser user);
        Task<string> GenerateEmailConfirmationTokenAsync(AppUser user);
        Task<ResultViewModel> ConfirmEmailAsync(AppUser user, string token);
        Task<ResultViewModel> ResetPasswordAsync(AppUser user, string token, string newPassword);
    }
}
