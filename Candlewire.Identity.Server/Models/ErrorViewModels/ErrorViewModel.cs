// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Models.BaseViewModels;
using IdentityServer4.Models;

namespace Candlewire.Identity.Server.Models.ErrorViewModels
{
    public class ErrorViewModel: BaseViewModel
    {
        public ErrorMessage Error { get; set; }
    }
}