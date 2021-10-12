﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Enums
{
    public enum TokenValidationStatus
    {
        Expired,
        WrongUser,
        WrongPurpose,
        SecurityStamp
    }
}
