// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Candlewire.Identity.Server.Options
{
    public class AccountOptions
    {
        public static Boolean AllowLocalLogin = true;
        public static Boolean AllowRememberLogin = true;
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        public static Boolean ShowLogoutPrompt = true;
        public static Boolean AutomaticRedirectAfterSignOut = false;

        // specify the Windows authentication scheme being used
        public static readonly String WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        // if user uses windows auth, should we load the groups from windows
        public static Boolean IncludeWindowsGroups = false;

        public static String InvalidCredentialsErrorMessage = "Invalid username or password";
    }
}
