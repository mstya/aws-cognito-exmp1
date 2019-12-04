using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using AWSCongito.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AWSCongito.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly ILogger<RegisterViewModel> _logger;
        private readonly CognitoUserPool _pool;

        public AccountController(
            UserManager<CognitoUser> userManager,
            SignInManager<CognitoUser> signInManager,
            ILogger<RegisterViewModel> logger,
            CognitoUserPool pool)
        {
            _userManager = userManager as CognitoUserManager<CognitoUser>;
            _signInManager = signInManager;
            _logger = logger;
            _pool = pool;
        }
        
        [HttpGet]
        public ActionResult Register()
        {
            var model = new RegisterViewModel();;
            return this.View(model);
        }

        [HttpPost]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (this.ModelState.IsValid)
            {
                CognitoUser user = _pool.GetUser(model.UserName);
                user.Attributes.Add(CognitoAttribute.Email.AttributeName, model.Email);
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return this.RedirectToAction("ConfirmAccount", "Account");
                }
                
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return this.View(model);
        }

        [HttpPost]
        public async Task<ActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return this.RedirectToAction("Login", "Account");
        }

        [HttpGet]
        public async Task<ActionResult> Login()
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);

            return this.View(new LoginViewModel());
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result =
                    await _signInManager.PasswordSignInAsync(model.UserName, model.Password, lockoutOnFailure: false, isPersistent: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return this.RedirectToAction("Index", "Home");
                }
                else if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = "", RememberMe = model.RememberMe });
                }
                else if (result.IsCognitoSignInResult())
                {
                    if (result is CognitoSignInResult cognitoResult)
                    {
                        if (cognitoResult.RequiresPasswordChange)
                        {
                            _logger.LogWarning("User password needs to be changed");
                            return this.RedirectToAction("ChangePassword", "Account");
                        }
                        else if (cognitoResult.RequiresPasswordReset)
                        {
                            _logger.LogWarning("User password needs to be reset");
                            return this.RedirectToAction("ResetPassword", "Account");
                        }
                    }
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }

            return View(model);
        }

        [HttpGet]
        public ActionResult ChangePassword()
        {
            return View(new ChangePasswordViewModel());
        }
        
        [HttpPost]
        public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to retrieve user.");
            }
            
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation("Changed password for user with ID '{UserId}'.", user.UserID);
                return this.RedirectToAction("Index", "Home");
            }
            else
            {
                _logger.LogInformation("Unable to change password for user with ID '{UserId}'.", user.UserID);
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError(item.Code, item.Description);
                }
                return View(model);
            }
        }

        [HttpGet]
        public ActionResult ConfirmAccount()
        {
            return this.View(new ConfirmAccountViewModel());
        }
        
        [HttpPost]
        public async Task<ActionResult> ConfirmAccount(ConfirmAccountViewModel model)
        {
            if (ModelState.IsValid)
            {
                var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name).Value;
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return NotFound($"Unable to load user with ID '{userId}'.");
                }

                var result = await _userManager.ConfirmSignUpAsync(user, model.Code, true);
                if (!result.Succeeded)
                {
                    throw new InvalidOperationException($"Error confirming account for user with ID '{userId}':");
                }
                else
                {
                    return this.RedirectToAction("Login", "Account");
                }
            }

            return this.View(new ConfirmAccountViewModel());
        }
    }
}