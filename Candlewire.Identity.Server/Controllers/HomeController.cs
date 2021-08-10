// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Candlewire.Identity.Server.Attributes;
using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Managers;
using Candlewire.Identity.Server.Models.ErrorViewModels;
using Candlewire.Identity.Server.Models.HomeViewModels;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.ServerControllers
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IWebHostEnvironment _environment;
        private readonly ClientManager _clientManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        public HomeController(IIdentityServerInteractionService interaction, IWebHostEnvironment environment, ClientManager clientManager, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<HomeController> logger, IConfiguration configuration)
        {
            _interaction = interaction;
            _environment = environment;
            _clientManager = clientManager;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _configuration = configuration;
        }

        public async Task<IActionResult> Index()
        {
            if (User?.Identity.IsAuthenticated == true)
            {
                var user = await _userManager.GetUserAsync(User).ConfigureAwait(false);
                var model = await BuildIndexViewModel();
                return View("Index", model);
            }
            else
            {
                return RedirectToAction("Login", "Account");
            }
        }

        private async Task<IndexViewModel> BuildIndexViewModel()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var roles = (await _userManager.GetRolesAsync(user)).ToList();
            var clients = await _clientManager.GetClients(user, roles ?? new List<String>());
            var claims = await _userManager.GetClaimsAsync(user);
            var lastName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("family_name"))?.Value;
            var firstName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("given_name"))?.Value;
            var fullName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("full_name"))?.Value;
            var userName = claims.FirstOrDefault(a => a.Type.ToLower().Equals("preferred_username"))?.Value;

            var model = new IndexViewModel
            {
                FirstName = firstName,
                LastName = lastName,
                Username = userName,
                Clients = (clients.Select(a => new ClientViewModel
                {
                    ClientName = a.ClientName,
                    ClientDescription = a.Description,
                    ClientImage = a.LogoUri,
                    ClientUri = a.ClientUri
                })).ToList()
            };
            return model;
        }


        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();
            var message = await _interaction.GetErrorContextAsync(errorId);
            if (message != null)
            {
                // Only show errors in development
                vm.Error = message;
                if (!_environment.IsDevelopment())
                {
                    message.ErrorDescription = null;
                }
            }

            return View("Error", vm);
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }
    }
}