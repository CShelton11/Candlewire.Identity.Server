// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Models.BaseViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace Candlewire.Identity.Server.Models.AccountViewModels
{
    public class LoginViewModel : LoginInputModel
    {
        public Boolean AllowRememberLogin { get; set; } = true;
        public Boolean EnableLocalLogin { get; set; } = true;
        public IEnumerable<ExternalProvider> ExternalProviders { get; set; } = Enumerable.Empty<ExternalProvider>();
        public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));
        public Boolean IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count() == 1;
        public String ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;
    }

    public class LoginInputModel: BaseViewModel
    {
        [Required]
        [Display(Name = "Email Address")]
        public String Email { get; set; }

        [Required]
        [Display(Name = "Password")]
        public String Password { get; set; }
        public Boolean RememberLogin { get; set; }
        public String ReturnUrl { get; set; }
    }
}