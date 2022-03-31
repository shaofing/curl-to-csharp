using CurlToCSharp.Models;

namespace CurlToCSharp.Services;

public interface IConverterRequestService
{
    ConvertResult<List<HttpResponseMessage>> GetResponses(CurlOptions curlOptions);
}
