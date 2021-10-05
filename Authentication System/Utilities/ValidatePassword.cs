using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Authentication_System.Utilities
{
    public class ValidatePassword
    {
        private const string UPPERCASE_PATTERN = @"[A-Z]+"; //
        private const string LOWERCASE_PATTERN = @"[a-z]+";
        private const string DIGIT_PATTERN = @"[0-9]+";
        private const string SPECIAL_CHARACTER_PATTERN = @"[!\]\[#$@%*+\\&/\-.]"; //[^A-Za-z0-9]  "'(),/:;<=>?\^_`{|}~]

        private static PasswordOptions passwordOption;

        public ValidatePassword(IOptions<IdentityOptions> identityOptions)
        {
            passwordOption = identityOptions.Value.Password;
        }

        public bool IsValidate(string password, out List<string> errors)
        {
            errors = new List<string>();

            if (password.Length < passwordOption.RequiredLength)
            {
                errors.Add($"Password Lenght Should Should Be {passwordOption.RequiredLength} Or More");
            }
            if (passwordOption.RequireUppercase && !Regex.IsMatch(password, UPPERCASE_PATTERN))
            {
                errors.Add($"The password should contain an Uppercase");
            }
            if (passwordOption.RequireLowercase && !Regex.IsMatch(password, LOWERCASE_PATTERN))
            {
                errors.Add($"The password should contain a Lowercase");
            }
            if (passwordOption.RequireDigit && !Regex.IsMatch(password, DIGIT_PATTERN))
            {
                errors.Add($"The password should contain a Number");
            }
            if (passwordOption.RequireNonAlphanumeric && !Regex.IsMatch(password, SPECIAL_CHARACTER_PATTERN))
            {
                errors.Add($"The password should contain a Special Character");
            }


            return errors.Count != 0 ? false : true;
        }

    }
}
