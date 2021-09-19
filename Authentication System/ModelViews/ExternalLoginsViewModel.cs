using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews
{
    public class ExternalLoginsViewModel
    {
        public ExternalLoginsViewModel()
        {
            Providers = new List<AuthenticationScheme>();
        }
        public string ReturnUrl { get; set; }

        public IList<AuthenticationScheme> Providers { get; set; }
    }
}
