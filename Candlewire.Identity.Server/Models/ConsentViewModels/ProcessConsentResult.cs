// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Models.BaseViewModels;
using System;

namespace Candlewire.Identity.Server.Models.ConsentViewModels
{
    public class ProcessConsentResult: BaseViewModel
    {
        public Boolean IsRedirect => RedirectUri != null;
        public String RedirectUri { get; set; }
        public String ClientId { get; set; }

        public Boolean ShowView => ViewModel != null;
        public ConsentViewModel ViewModel { get; set; }

        public Boolean HasValidationError => ValidationError != null;
        public String ValidationError { get; set; }
    }
}
