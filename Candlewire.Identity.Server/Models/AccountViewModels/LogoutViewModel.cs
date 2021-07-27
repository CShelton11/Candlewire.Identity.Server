// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Models.BaseViewModels;
using System;

namespace Candlewire.Identity.Server.Models.AccountViewModels
{
    public class LogoutViewModel : LogoutInputModel
    {
        public Boolean ShowLogoutPrompt { get; set; } = true;
        public String PostLogoutRedirectUri { get; set; }
        public String ClientName { get; set; }
        public String SignOutIframeUrl { get; set; }
        public Boolean AutomaticRedirectAfterSignOut { get; set; } = false;
        public Boolean TriggerExternalSignout => ExternalAuthenticationScheme != null;
        public String ExternalAuthenticationScheme { get; set; }
    }

    public class LogoutInputModel: BaseViewModel
    {
        public String LogoutId { get; set; }
        public Boolean Authenticated { get; set; }
    }
}
