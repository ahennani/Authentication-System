using Authentication_System.Models.Configuration;
using Authentication_System.Models.Email;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;

namespace Authentication_System.Services
{
    public class EmailService : IEmailService
    {

        #region Private Attributes

        #region Email Templates Path

        private static readonly string EmailTemplatePath = @"EmailTemplate/{0}.html";
        private static readonly string ForgotPasswordEmailToUser = string.Format(EmailTemplatePath, "ForgotPasswordToken");
        private static readonly string EmailConfirmationLinkToUser = string.Format(EmailTemplatePath, "EmailConfirmation");

        #endregion

        #region Email Subjects

        private static readonly string ForgotPasswordSubject = "Reset Your Password";
        private static readonly string EmailConfirmationSubject = "Confirm Your Email Address";

        #endregion

        #endregion

        private EmailConfiguration _emailConfiguration = new EmailConfiguration();

        //public EmailService(IConfiguration configuration)
        //{
        //    configuration.Bind("EmainConfuguration", _emailConfiguration);
        //}
        public EmailService(IOptions<EmailConfiguration> emailConfiguration)
        {
            _emailConfiguration = emailConfiguration.Value;
        }

        #region Public Methods

        public async Task SendEmailForEmailConfirmationAsync(UserEmailOptions userEmailOptions)
        {
            userEmailOptions.Subject = EmailConfirmationSubject;
            //userEmailOptions.Resource = GetLinkedResource(userEmailOptions.ServerPath);
            userEmailOptions.Body = GetEmailBody(EmailConfirmationLinkToUser, userEmailOptions.PlaceHolders);

            await SendEmailAsync(userEmailOptions);
        }

        public async Task SendEmailForForgotPasswordAsync(UserEmailOptions userEmailOptions)
        {
            userEmailOptions.Subject = ForgotPasswordSubject;
            //userEmailOptions.Resource = GetLinkedResource(userEmailOptions.ServerPath);
            userEmailOptions.Body = GetEmailBody(ForgotPasswordEmailToUser, userEmailOptions.PlaceHolders);

            await SendEmailAsync(userEmailOptions);
        }

        #endregion

        #region Private Methods

        private async Task SendEmailAsync(UserEmailOptions userEmailOptions)
        {
            MailMessage mail = new MailMessage
            {
                Subject = userEmailOptions.Subject,
                Body = userEmailOptions.Body,
                From = new MailAddress(_emailConfiguration.SenderAddress, _emailConfiguration.SenderDisplayName),
                IsBodyHtml = _emailConfiguration.IsBodyHtml,
                BodyEncoding = Encoding.Default
            };

            foreach (var toEmail in userEmailOptions.ToEmails)
            {
                mail.To.Add(toEmail);
            }

            #region Attachments
            //var alternateView = AlternateView.CreateAlternateViewFromString(userEmailOptions.Body, null, MediaTypeNames.Text.Html);
            //if (userEmailOptions.Resource != null)
            //{
            //    alternateView.LinkedResources.Add(userEmailOptions.Resource);
            //    mail.AlternateViews.Add(alternateView);
            //}

            // Add Attachments To Our Email
            //if (userEmailOptions.Attachments != null && userEmailOptions.Attachments.Any())
            //{
            //    foreach (var attachment in userEmailOptions.Attachments)
            //    {
            //        var file = new Attachment(attachment.FileStream, attachment.FileName, attachment.MediaType);
            //        mail.Attachments.Add(file);
            //    }
            //}

            //mail.BodyEncoding = Encoding.Default;
            #endregion

            using (var smtp = new SmtpClient())
            {
                smtp.Host = _emailConfiguration.Host;
                smtp.Port = _emailConfiguration.Port;
                smtp.EnableSsl = _emailConfiguration.EnableSsl;
                smtp.UseDefaultCredentials = _emailConfiguration.UseDefaultCredentials;
                var t1 = _emailConfiguration.UserName;
                var t2 = _emailConfiguration.Password;
                smtp.Credentials =  new NetworkCredential(_emailConfiguration.UserName, _emailConfiguration.Password);

                await smtp.SendMailAsync(mail);
            }
        }

        private string GetEmailBody(string filePath, List<KeyValuePair<string, string>> placeholders)
        {

            var body = File.ReadAllText(filePath, Encoding.Default);

            if (!string.IsNullOrEmpty(body) && placeholders != null)
            {
                foreach (var placeholder in placeholders)
                {
                    if (body.Contains(placeholder.Key))
                    {
                        body = body.Replace(placeholder.Key, placeholder.Value);
                    }
                }
            }

            return body;
        }

        // Add Logo To Our Email
        //private LinkedResource GetLinkedResource(string serverPath)
        //{
        //    return new LinkedResource("wwwroot/logo.png", "image/png")
        //    {
        //        ContentId = "logo"
        //    };

        //    return null;
        //}

        #endregion

    }
}
