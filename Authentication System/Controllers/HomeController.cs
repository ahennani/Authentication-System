using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication_System.ModelViews.Error;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Authentication_System.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [AllowAnonymous]
        public async Task<IActionResult> Index()
        {
            return await Task.Run(()=> View());
        }

        [Authorize]
        public async Task<IActionResult> Privacy()
        {
            return await Task.Run(() => View());
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public async Task<IActionResult> ErrorAsync()
        {
            return await Task.Run(() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier }));
        }
    }
}
