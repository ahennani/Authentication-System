using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Authentication_System.Utilities
{
    class ValidatePassword
    {
        public const int MIN_LENGTH = 32;
        public const int MAN_LENGTH = 8;
        private const string UPPERCASE_PATTERN = @"[A-Z]+"; //
        private const string LOWERCASE_PATTERN = @"[a-z]+";
        private const string DIGIT_PATTERN = @"[0-9]+";
        private const string SPECIAL_CHARACTER_PATTERN = @"[!\]\[#$@%*+\\&/\-.]"; //[^A-Za-z0-9]  "'(),/:;<=>?\^_`{|}~]


        public static bool IsValidate(string password, out List<string> errors)
        {
            errors = new List<string>();

            if (password.Length < MAN_LENGTH)
            {
                errors.Add($"Password Lenght Should Should Be {MAN_LENGTH} Or More");
            }
            if (password.Length > MIN_LENGTH)
            {
                errors.Add($"Password Lenght Should Should Be {MIN_LENGTH} Or Less");
            }
            if (!Regex.IsMatch(password, UPPERCASE_PATTERN))
            {
                errors.Add($"The password should contain an Uppercase");
            }
            if (!Regex.IsMatch(password, LOWERCASE_PATTERN))
            {
                errors.Add($"The password should contain a Lowercase");
            }
            if (!Regex.IsMatch(password, DIGIT_PATTERN))
            {
                errors.Add($"The password should contain a Number");
            }
            if (!Regex.IsMatch(password, SPECIAL_CHARACTER_PATTERN))
            {
                errors.Add($"The password should contain a Special Character");
            }


            return errors.Count != 0 ? false : true;
        }

    }
}
