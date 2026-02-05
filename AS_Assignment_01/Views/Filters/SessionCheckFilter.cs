using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Identity;
using AS_Assignment_01.Models;

namespace AS_Assignment_01.Filters
{
    public class SessionCheckFilter : IActionFilter
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public SessionCheckFilter(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            var user = context.HttpContext.User;
            if (user.Identity != null && user.Identity.IsAuthenticated)
            {
                // Use synchronous Result for filter if not using async filter
                var loggedInUser = _userManager.GetUserAsync(user).GetAwaiter().GetResult();
                var currentSessionId = context.HttpContext.Session.GetString("AuthSessionId");

                if (loggedInUser != null && loggedInUser.CurrentSessionId != currentSessionId)
                {
                    context.HttpContext.Response.Cookies.Delete(".AspNetCore.Identity.Application");
                    context.Result = new RedirectToActionResult("Login", "Account", new { error = "MultipleLogins" });
                }
            }
        }

        public void OnActionExecuted(ActionExecutedContext context) { }
    }
}