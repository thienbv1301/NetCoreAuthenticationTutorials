using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SimpleAuthenticationApi.Helpers
{
    public static class Role
    {
        public const string Admin = "ADMIN";
        public const string User = "USER";
        public const string AdminOrUser = Admin + "," + User;
    }
}
