// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;

namespace Candlewire.Identity.Server.Options
{
    public class ConsentOptions
    {
        public static Boolean EnableOfflineAccess = true;
        public static String OfflineAccessDisplayName = "Offline Access";
        public static String OfflineAccessDescription = "Access to your applications and resources, even when you are offline";

        public static readonly String MustChooseOneErrorMessage = "You must pick at least one permission";
        public static readonly String InvalidSelectionErrorMessage = "Invalid selection";
    }
}
