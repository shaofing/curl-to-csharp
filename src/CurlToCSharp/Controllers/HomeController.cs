using CurlToCSharp.Models;
using CurlToCSharp.Services;

using Microsoft.AspNetCore.Mvc;

namespace CurlToCSharp.Controllers;

public class HomeController : Controller
{
    public HomeController()
    {

    }

    [Route("")]
    public IActionResult Index()
    {
        return View();
    }

    [Route("/error")]
    public IActionResult Error()
    {
        return StatusCode(500, new ConvertResult<string>(new List<string> { "Internal server error, please open an issue" }));
    }
}
