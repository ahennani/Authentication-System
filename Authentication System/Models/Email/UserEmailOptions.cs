using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Models.Email
{
    public class UserEmailOptions
    {
        public UserEmailOptions()
        {
            ToEmails = new();
        }
        public List<string> ToEmails { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public string Code { get; set; }
        public string Token { get; set; }
        public List<KeyValuePair<string, string>> PlaceHolders { get; set; }

        //public string ServerPath { get; set; }
        //public LinkedResource Resource { get; set; }
        //public List<EmailAttachment> Attachments { get; set; }
    }
}
