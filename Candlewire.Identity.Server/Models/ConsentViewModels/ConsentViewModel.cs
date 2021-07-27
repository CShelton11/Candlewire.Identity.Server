// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;

namespace Candlewire.Identity.Server.Models.ConsentViewModels
{
    public class ConsentViewModel : ConsentInputModel
    {
        public String ClientName { get; set; }
        public String ClientUrl { get; set; }
        public String ClientLogoUrl { get; set; }
        public Boolean AllowRememberConsent { get; set; }

        public IEnumerable<ScopeViewModel> IdentityScopes { get; set; }
        public IEnumerable<ScopeViewModel> ResourceScopes { get; set; }
    }

    public class ConsentInputModel: BaseViewModel
    {
        public String Button { get; set; }
        public IEnumerable<String> ScopesConsented { get; set; }
        public Boolean RememberConsent { get; set; }
        public String ReturnUrl { get; set; }
    }
}
