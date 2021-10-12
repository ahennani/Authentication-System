using Authentication_System.Models.Email;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Services
{
    public interface IEmailService
    {
        Task SendEmailForEmailConfirmationAsync(UserEmailOptions userEmailOptions);

        Task SendEmailForForgotPasswordAsync(UserEmailOptions userEmailOptions);
    }
}
