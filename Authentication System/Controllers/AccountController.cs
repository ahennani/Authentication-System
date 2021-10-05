using Authentication_System.Extensions;
using Authentication_System.Managers;
using Authentication_System.Models;
using Authentication_System.ModelViews;
using Authentication_System.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication_System.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly IAccountManager _accountManager;

        public AccountController(IAccountManager accountManager)
        {
            this._accountManager = accountManager;
        }

        /////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////< Signup >//////////////////////////////////////////

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Signup(string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            var model = new AccountSignupViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProviders()
                }
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signup(AccountSignupViewModel model, string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            model.ExternalLogins = new ExternalLoginsViewModel()
            {
                ReturnUrl = returnUrl,
                Providers = await _accountManager.GetExternalProviders()
            };

            if (ModelState.IsValid)
            {
                var user = _accountManager.GetAppUserByEmail(model.Email);
                if (user is not null)
                {
                    ModelState.AddModelError(string.Empty, "Email Is Already Taken !!");
                    return View(model);
                }


                var validateResult = _accountManager.CheckPasswordValidation(model.Password);
                if (!validateResult.IsValid)
                {
                    foreach (var error in validateResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }

                var result = await _accountManager.CreateAppUserAsync(model);
                if (!result.Succeed)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }

                if (Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }

                return Redirect("/");
            }

            return View(model);
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////< Login >//////////////////////////////////////////

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            var model = new AccountLoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProviders()
                }
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(AccountLoginViewModel model, string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            model = new AccountLoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProviders()
                }
            };

            if (ModelState.IsValid)
            {
                var result = await _accountManager.PasswordSignInAsync(model);
                if (result is not null)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }


                if (Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }

                return Redirect("/");
            }

            return View(model);
        }


        //////////////////////////////////////////< ExternalLogin >//////////////////////////////////////////
        [HttpPost]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction(String.Empty, "Home");
            }


            // /Account/ExternalLoginCallback?ReturnUrl=returnUrl
            var redirectUri = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl, Provider = provider });

            var properties = _accountManager.ConfigureExternalAuthenticationProperties(provider, redirectUri);

            return new ChallengeResult(provider, properties);
        }


        [AcceptVerbs("GET", "POST")]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string provider, string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            var model = new AccountLoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProviders()
                }
            };

            if (remoteError is not null)
            {
                ModelState.AddModelError(string.Empty, $"Error from External Provider: {remoteError}");
                return View(nameof(SignIn), model);
            }

            var user = _accountManager.GetExternalAppUser();

            if (user is null)
            {
                var result = await _accountManager.CreateExternalAppUserAsync(provider);
            }
            else
            {
                if (!_accountManager.IsProviderExist(user, provider))
                {
                    var isAdded = _accountManager.AddAppUserProvider(user, provider);
                }
                await _accountManager.SignInAsync(user);
            }

            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return Redirect("/");
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////< Signout >//////////////////////////////////////////

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _accountManager.SignOutAsync();
            return Redirect(Url.Action("Index", "Home"));
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////< Remote Methods >//////////////////////////////////////////

        [AllowAnonymous]
        [AcceptVerbs("Get", "Post")]
        public IActionResult IsValidePassword(string password)
        {
            var result = _accountManager.CheckPasswordValidation(password);

            if (result.IsValid)
            {
                return Json(true);
            }

            var res = String.Join("<br />", result.Errors);
            return Json(res);
        }

    }
}
