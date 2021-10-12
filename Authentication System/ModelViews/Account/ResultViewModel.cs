using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.ModelViews.Account
{
    public class ResultViewModel
    {
        public ResultViewModel()
        {
            Errors = new();
        }
        public bool Succeeded { get { return Errors.Count <= 0; } } 

        public List<string> Errors { get; set; }
    }
}
