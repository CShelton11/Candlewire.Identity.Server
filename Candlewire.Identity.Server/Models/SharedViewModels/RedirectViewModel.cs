// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Models.BaseViewModels;
using System;

namespace Candlewire.Identity.Server.Models.SharedViewModels
{
    public class RedirectViewModel: BaseViewModel
    {
        public String RedirectUrl { get; set; }
    }
}