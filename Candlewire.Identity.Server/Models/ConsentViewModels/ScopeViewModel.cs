// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Models.BaseViewModels;
using System;

namespace Candlewire.Identity.Server.Models.ConsentViewModels
{
    public class ScopeViewModel: BaseViewModel
    {
        public String Name { get; set; }
        public String DisplayName { get; set; }
        public String Description { get; set; }
        public Boolean Emphasize { get; set; }
        public Boolean Required { get; set; }
        public Boolean Checked { get; set; }
    }
}
