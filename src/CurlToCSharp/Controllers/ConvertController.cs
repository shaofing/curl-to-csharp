using CurlToCSharp.Models;
using CurlToCSharp.Services;

using Microsoft.AspNetCore.Mvc;

namespace CurlToCSharp.Controllers;

[Route("[controller]")]
public class ConvertController : Controller
{
    private readonly IConverterService _converterService;
    private readonly IConverterRequestService _converterRequestService;

    private readonly ICommandLineParser _commandLineParser;

    public ConvertController(IConverterService converterService,
        IConverterRequestService converterRequestService,
        ICommandLineParser commandLineParser
        )
    {
        _converterService = converterService;
        _commandLineParser = commandLineParser;
        _converterRequestService = converterRequestService;
    }

    [HttpPost]
    public IActionResult Post([FromBody] ConvertModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(
                new ConvertResult<ConvertModel>(
                    ModelState.SelectMany(r => r.Value.Errors.Select(e => e.ErrorMessage))
                        .ToArray()));
        }

        var parseResult = _commandLineParser.Parse(new Span<char>(model.Curl.ToCharArray()));
        if (!parseResult.Success)
        {
            return BadRequest(parseResult);
        }

        var csharp = _converterService.ToCsharp(parseResult.Data);
        csharp.AddWarnings(parseResult.Warnings);

        return Ok(csharp);
    }

    

    [HttpPost]
    [Route("/convert/send")]
    public IActionResult Send([FromBody] ConvertModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(
                new ConvertResult<ConvertModel>(
                    ModelState.SelectMany(r => r.Value.Errors.Select(e => e.ErrorMessage))
                        .ToArray()));
        }

        var parseResult = _commandLineParser.Parse(new Span<char>(model.Curl.ToCharArray()));
        if (!parseResult.Success)
        {
            return BadRequest(parseResult);
        }


        var responseResult = _converterRequestService.GetResponses(parseResult.Data);

        responseResult.AddWarnings(parseResult.Warnings);

        var lst = responseResult.Data.Select(rsp =>
        {
            rsp.EnsureSuccessStatusCode();
            return new { rsp.StatusCode, Content = rsp.Content.ReadAsStringAsync().Result };
        }
        ).ToList();

        var rr = new ConvertResult<dynamic>(lst, responseResult.Errors, responseResult.Warnings);

        return Ok(rr);
    }


    [HttpGet]
    [Route("/convert/getresult")]
    public async Task<IActionResult> GetResult()
    {
        var handler = new HttpClientHandler();
        handler.UseCookies = false;

        using var httpClient = new HttpClient();

        using var request = new HttpRequestMessage(new HttpMethod("GET"), "https://www.baidu.com");
            
        request.Headers.TryAddWithoutValidation("Cookie", "SessionId=437b27169b6b4349a388038329eeb900");

        var response = await httpClient.SendAsync(request);
        var str = await response.Content.ReadAsStringAsync();

        return Content(str, "text/html;charset=utf-8");

    }
    
}
