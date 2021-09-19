using Authentication_System.Extensions;
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
        private readonly AppDbContext _context;
        private readonly IAuthenticationSchemeProvider authenticationSchemeProvider;
        private readonly ManageUsers manageUsers;

        public AccountController(
                                    AppDbContext context, 
                                    IAuthenticationSchemeProvider authenticationSchemeProvider, 
                                    ManageUsers manageUsers
                                )
        {
            this._context = context;
            this.authenticationSchemeProvider = authenticationSchemeProvider;
            this.manageUsers = manageUsers;
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////< Signup >//////////////////////////////////////////

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Signup(string returnUrl)
        {
            returnUrl = returnUrl ?? "/";
            var model = new AccountSignupViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = (await this.authenticationSchemeProvider.GetAllSchemesAsync())
                                .Where(p => !p.Name.Equals("Cookies"))
                                .ToList()
                }
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signup(AccountSignupViewModel model, string returnUrl)
        {
            returnUrl = returnUrl ?? "/";

            model.ExternalLogins = new ExternalLoginsViewModel()
            {
                ReturnUrl = returnUrl,
                Providers = (await this.authenticationSchemeProvider.GetAllSchemesAsync())
                                .Where(p => !p.Name.Equals("Cookies"))
                                .ToList()
            };


            if (ModelState.IsValid)
            {
                var user = this._context.AppUsers
                                        .Where(u => u.Username == model.Email)
                                        .Where(u => u.Email == model.Email)
                                        .FirstOrDefault();
                if (user is not null)
                {
                    ModelState.AddModelError(string.Empty, "Email Is Already Taken !!");
                    return View(model);
                }

                var isValidPassword = ValidatePassword.IsValidate(model.Password, out List<string> passwordValidationErrors);
                if (!isValidPassword)
                {
                    foreach (var error in passwordValidationErrors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return View(model);
                }

                user = new AppUser()
                {
                    Username = model.Email,
                    Firstname = model.FirstName,
                    Lastname = model.LastName,
                    Email = model.Email,
                    Password = model.Password
                };
                this._context.AppUsers.Add(user);
                var result = this._context.SaveChanges();

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
            var model = new AccountLoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = (await this.authenticationSchemeProvider.GetAllSchemesAsync())
                                .Where(p => !p.Name.Equals("Cookies"))
                                .ToList()
                }
            };

            var count = this._context.AppUsers.Count();

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(AccountLoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = this._context.AppUsers
                                        .Where(u => u.Username == model.Email)
                                        .Where(u => u.Password == model.Password)
                                        .FirstOrDefault();
                if (user is null)
                {
                    ModelState.AddModelError(string.Empty, "The password Or Email Is Not Correct !!");
                    return View(model);
                }

                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()));
                claims.Add(new Claim(ClaimTypes.Name, user.Username));
                claims.Add(new Claim(ClaimTypes.Name, user.Email));
                claims.Add(new Claim(ClaimTypes.GivenName, user.Firstname));
                claims.Add(new Claim(ClaimTypes.Surname, user.Lastname));

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                await HttpContext.SignInAsync(claimsPrincipal);
                return Redirect("/");
            }

            model = new AccountLoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = (await this.authenticationSchemeProvider.GetAllSchemesAsync())
                                            .Where(p => !p.Name.Equals("Cookies"))
                                            .ToList()
                }
            };

            return View(model);
        }


        [HttpPost]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("", "Home");
            }

            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl, Provider = provider }); // /Account/ExternalLoginCallback?ReturnUrl=returnUrl

            var authenticationProperties = new AuthenticationProperties() { RedirectUri = redirectUrl };

            return new ChallengeResult(provider, authenticationProperties);
        }


        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string provider, string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            var scheme = User.Claims.FirstOrDefault(c => c.Type == ".AuthScheme")?.Value;

            var model = new AccountLoginViewModel()
            {
                ExternalLogins = new ExternalLoginsViewModel()
                {
                    ReturnUrl = returnUrl,
                    Providers = (await this.authenticationSchemeProvider.GetAllSchemesAsync())
                                .Where(p => !p.Name.Equals("Cookies"))
                                .ToList()
                }
            };

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from External Provider: {remoteError}");
                return View(nameof(SignIn), model);
            }

            List<Claim> claims = null;
            //var username = (HttpContext.User.Claims.Where(c => c.Type == ClaimTypes.Email).FirstOrDefault()).Value;
            var username = HttpContext.User.Claims.ToList().GetClaim(ClaimTypes.Email);
            var user = this.manageUsers.FindAppUser(username);

            if (user is null)
            {
                claims = HttpContext.User.Claims.ToList();
                user = this.manageUsers.AddNewUser(provider, claims);
            }
            else
            {
                if (!(user.Providers.Any(p => p.Name.Equals(provider))))
                {
                    user = this.manageUsers.AddProviderToUser(user, provider);
                }

                this.manageUsers.GetUserClaims(username, out claims);
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            await HttpContext.SignInAsync(claimsPrincipal);
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
            await HttpContext.SignOutAsync();
            return Redirect(Url.Action("Index", "Home"));
        }


        /////////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////< Remote Methods >//////////////////////////////////////////

        [AllowAnonymous]
        [AcceptVerbs("Get", "Post")]
        public IActionResult IsValidePassword(string password)
        {
            var isValid = ValidatePassword.IsValidate(password, out List<string> errors);

            if (isValid)
            {
                return Json(true);
            }

            var res = String.Join("<br />", errors);
            return Json(res);
        }

    }
}
