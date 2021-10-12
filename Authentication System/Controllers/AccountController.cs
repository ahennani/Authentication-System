using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Authentication_System.Managers;
using Authentication_System.ModelViews.Account;
using Microsoft.Extensions.Logging;

namespace Authentication_System.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly IAccountManager _accountManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(IAccountManager accountManager, ILogger<AccountController> logger)
        {
            this._accountManager = accountManager;
            this._logger = logger;
        }

        #region Signup

        [HttpGet, AllowAnonymous]
        public async Task<IActionResult> Signup(string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            var model = new SignupViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProvidersAsync()
                }
            };

            return View(model);
        }

        [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
        public async Task<IActionResult> Signup(SignupViewModel model, string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            model.ExternalLogins = new ExternalLoginsViewModel()
            {
                ReturnUrl = returnUrl,
                Providers = await _accountManager.GetExternalProvidersAsync()
            };

            if (ModelState.IsValid)
            {
                var user = await _accountManager.GetAppUserByEmailAsync(model.Email);
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
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }

                user = await _accountManager.GetAppUserByEmailAsync(model.Email);
                await _accountManager.SendConfirmationEmailTokenEmailAsync(user);

                if (Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }

                return Redirect("/");
            }

            return View(model);
        }

        #endregion

        #region Login

        [HttpGet, AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            var model = new LoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProvidersAsync()
                }
            };

            return View(model);
        }

        [HttpPost, AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            model.ExternalLogins = new ExternalLoginsViewModel()
            {
                ReturnUrl = returnUrl,
                Providers = await _accountManager.GetExternalProvidersAsync()
            };

            if (ModelState.IsValid)
            {
                var result = await _accountManager.PasswordSignInAsync(model);
                if (result.Succeeded is false)
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
        [HttpPost, AllowAnonymous]
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

        [AcceptVerbs("GET", "POST"), AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string provider, string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            var model = new LoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = await _accountManager.GetExternalProvidersAsync()
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

        #endregion

        #region Signout

        [HttpGet, Authorize]
        public async Task<IActionResult> Logout()
        {
            await _accountManager.SignOutAsync();
            return Redirect(Url.Action("Index", "Home"));
        }

        #endregion

        #region Change Password

        [HttpGet, Route("change-password")]
        public async Task<IActionResult> ChangePassword()
        {
            return await Task.Run(() => View(new ChangePasswordViewModel()));
        }

        [HttpPost, Route("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var validateResult = _accountManager.CheckPasswordValidation(model.NewPassword);
                if (!validateResult.IsValid)
                {
                    foreach (var error in validateResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }

                var result = _accountManager.ChangePasswordAsync(model);
                if (result.Succeeded)
                {
                    //ModelState.Clear();
                    model.IsSuccess = true;
                    return View(model);
                }

                if (result.Errors.Count > 0)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(String.Empty, error);
                    }
                }
            }

            //return View(model); 
            return await Task.Run(() => View(model));
        }

        #endregion

        #region Forgot Password

        [HttpGet, AllowAnonymous]
        public async Task<IActionResult> ForgotPassword()
        {
            return await Task.Run(() => View());
        }

        [AllowAnonymous, HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _accountManager.SendForgotPasswordEmailAsync(model.Email);
                ModelState.Clear();
                model.IsSuccess = result;
                return View(model);
            }
            return View(model);
        }

        #endregion

        #region Reset Password

        [AllowAnonymous, Route("reset-password")]
        public async Task<IActionResult> ResetPassword(string uid, string token)
        {
            var model = new ResetPasswordViewModel()
            {
                Token = token,
                UserId = uid
            };

            //var isValidToken = _accountManager.

            return await Task.Run(() => View(model));
        }

        [AllowAnonymous, HttpPost, Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var validateResult = _accountManager.CheckPasswordValidation(model.Password);
                if (!validateResult.IsValid)
                {
                    foreach (var error in validateResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }

                var result = await _accountManager.ResetPasswordAsync(model);
                if (result.Succeeded)
                {
                    ModelState.Clear();
                    model.IsSuccess = true;
                    return View(model);
                }
                else if (result?.Errors?.Count > 0)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(String.Empty, error);
                    }
                }
            }
            return await Task.Run(() => View(model));
        }

        #endregion

        #region Confirm Email

        [HttpGet, AllowAnonymous, Route("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string uid = null, string token = null, string email = null)
        {
            var model = new ConfirmEmailViewModel();
            if (!string.IsNullOrEmpty(uid) && !string.IsNullOrEmpty(token))
            {
                var result = await _accountManager.ConfirmUserEmailAsync(uid, token, email);
                if (result.Succeeded)
                {
                    model.IsConfirmed = true;
                    return View(model);
                }
            }

            model.Email = email;
            return View(model);
        }


        [HttpPost, AllowAnonymous, Route("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailViewModel model)
        {
            var user = await _accountManager.GetAppUserByEmailAsync(model.Email);
            if (user is not null)
            {
                if (user.EmailConfirmed)
                {
                    model.IsConfirmed = true;
                    return View(model);
                }

                var result = await _accountManager.SendConfirmationEmailTokenEmailAsync(user);
                if (result)
                {
                    ModelState.Clear();
                    model.IsSuccess = true;
                }
            }
            else
            {
                ModelState.AddModelError(String.Empty, "There is some issue in sending confirmation link. Please contact us.");
            }

            return View(model);
        }

        #endregion

        #region Remote Methods

        ////////////////////////////////////////< Verify Email >//////////////////////////////////////////

        [AcceptVerbs("GET", "POST"), AllowAnonymous]
        public async Task<IActionResult> VerifyEmail(string email)
        {
            if (!await _accountManager.IsEmailExistAsync(email))
            {
                return Json($"Email {email} is already in use.");
            }

            return Json(true);
        }

        [AcceptVerbs("Get", "Post"), AllowAnonymous]
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

        #endregion

    }
}
