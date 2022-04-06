using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Collections.Concurrent;

using CurlToCSharp.Models;

using Microsoft.Net.Http.Headers;

namespace CurlToCSharp.Services;

/// <summary>
/// 参考https://github.com/olsh/curl-to-csharp/blob/master/src/CurlToCSharp/Services/ConverterService.cs实现
/// </summary>
public class ConverterRequestService : IConverterRequestService
{
    internal static readonly string HttpClientForQtMessageCurlPrefixName = "HttpClientForQtMessageCurl";

    private readonly IHttpClientFactory _httpClientFactory;

    public ConverterRequestService(
        IHttpClientFactory httpClientFactory
        )
    {
        _httpClientFactory = httpClientFactory;
    }




    private void AddWarningsIfAny(CurlOptions curlOptions, ConvertResult<List<HttpResponseMessage>> result)
    {
        if (curlOptions.HasProxy && !IsSupportedProxy(curlOptions.ProxyUri))
        {
            result.Warnings.Add($"Proxy scheme \"{curlOptions.ProxyUri.Scheme}\" is not supported");
        }

        if (curlOptions.HasCertificate)
        {
            if (!IsSupportedCertificate(curlOptions.CertificateType))
            {
                result.Warnings.Add($"Certificate type \"{curlOptions.CertificateType}\" is not supported");
            }

            if (curlOptions.CertificateType == CertificateType.P12 && curlOptions.HasKey)
            {
                result.Warnings.Add("Key parameter is not supported when using a P12 certificate. The key parameter will be ignored");
            }
        }

        if (curlOptions.HasKey && !curlOptions.HasCertificate)
        {
            result.Warnings.Add("Key parameter cannot be used without a certificate. The key parameter will be ignored");
        }

        if (curlOptions.HasKey && !IsSupportedKey(curlOptions.KeyType))
        {
            result.Warnings.Add($"Key type \"{curlOptions.KeyType}\" is not supported");
        }
    }


    public ConvertResult<List<HttpResponseMessage>> GetResponses(CurlOptions curlOptions)
    {
        var result = new ConvertResult<List<HttpResponseMessage>>();

        AddWarningsIfAny(curlOptions, result);

        using var httpClient = GetHttpClient(curlOptions);

        var hrms = new List<HttpRequestMessage>();

        //发起多个请求, 前两个条件取反
        bool multipleRequests = !(curlOptions.HasDataPayload && !curlOptions.ForceGet) && !curlOptions.HasFormPayload && curlOptions.HasFilePayload;
        if (multipleRequests)
            hrms.AddRange(GetUploadFileRequests(curlOptions));
        else
            hrms.Add(GetSingleRequest(curlOptions));

        var tasks = new List<Task<HttpResponseMessage>>(hrms.Count);
        foreach (var itemRequest in hrms)
        {
            tasks.Add(Task.Run(async () =>
            {
                using (itemRequest)
                {
                    return await httpClient.SendAsync(itemRequest);
                }
            }));
        }

        Task.WaitAll(tasks.ToArray());

        var responses = tasks.Select(t => t.Result).ToList();
        result.Data = responses;
        return result;
    }

    object GetHttpClientLock = new object();

    private HttpClient GetHttpClient(CurlOptions curlOptions)
    {
        //是否创建新的HttpClient
        if (ShouldNewHttpClient(curlOptions))
        {
            var handler = CreateHttpClientHandler(curlOptions);
            return new HttpClient(handler);
        }
        else
        {
            //从HttpClientFactory获取HttpClient
            return _httpClientFactory.CreateClient(GetHttpClientName(curlOptions));
        }
    }

    private HttpClient GetHttpClient2(CurlOptions curlOptions)
    {
        if (ShouldGenerateHandler(curlOptions))
        {
            var handler = CreateHttpClientHandler(curlOptions);
            return new HttpClient(handler);
        }
        return new HttpClient();
    }

    private string GetHttpClientName(CurlOptions curlOptions)
    {
        //暂时只考虑这三种,情况下使用httpClientFactory ,减少Time-w
        /*
        bool HasCookies;    0b001
        bool IsCompressed;  0b010
        bool Insecure;      0b100
        */
        var i = (curlOptions.HasCookies ? 0b001 : 0)
            + (curlOptions.IsCompressed ? 0b010 : 0)
            + (curlOptions.Insecure ? 0b100 : 0);
        return $"{HttpClientForQtMessageCurlPrefixName}{i}";
    }

    /// <summary>
    /// 创建HttpClientHandler
    /// </summary>
    /// <param name="curlOptions"></param>
    /// <returns></returns>
    private HttpClientHandler CreateHttpClientHandler(CurlOptions curlOptions)
    {
        var handler = new HttpClientHandler();
        if (curlOptions.HasCookies)
            //这里设为false, 通过HttpRequestMessage 设置Cookie
            handler.UseCookies = false;
        if (curlOptions.HasProxy && IsSupportedProxy(curlOptions.ProxyUri))
            handler.Proxy = CreateWebProxy(curlOptions);
        if (curlOptions.IsCompressed)
            handler.AutomaticDecompression = DecompressionMethods.All;
        if (curlOptions.HasCertificate && IsSupportedCertificate(curlOptions.CertificateType))
            SetCertificate(handler, curlOptions);
        if (curlOptions.Insecure)
            handler.ServerCertificateCustomValidationCallback = (requestMessage, certificate, chain, policyErrors) => true;
        return handler;
    }

    /// <summary>
    /// 创建Web代理
    /// </summary>
    /// <param name="curlOptions"></param>
    /// <returns></returns>
    private WebProxy CreateWebProxy(CurlOptions curlOptions)
    {
        var proxy = new WebProxy(curlOptions.ProxyUri.ToString());

        if (curlOptions.UseDefaultProxyCredentials)
        {
            proxy.UseDefaultCredentials = true;
        }
        if (curlOptions.HasProxyUserName)
        {
            proxy.Credentials = new NetworkCredential(curlOptions.ProxyUserName, curlOptions.ProxyPassword);
        }
        return proxy;
    }

    #region 证书相关

    private void SetCertificate(HttpClientHandler handler, CurlOptions curlOptions)
    {
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;

        switch (curlOptions.CertificateType)
        {
            case CertificateType.P12:
                handler.ClientCertificates.Add(CreateP12Certificate(curlOptions));
                break;
#if NET5_0_OR_GREATER
            case CertificateType.Pem:
                //PEM certificates support requires .NET 5 and higher
                //Export to PFX is needed because of this bug https://github.com/dotnet/runtime/issues/23749#issuecomment-747407051
                handler.ClientCertificates.Add(CreatePemCertificate(curlOptions));
                break;
#endif
            default:
                throw new ArgumentOutOfRangeException(nameof(curlOptions.CertificateType), $"Unsupported certificate type {curlOptions.CertificateType}");
        }


    }

    private System.Security.Cryptography.X509Certificates.X509Certificate CreatePemCertificate(CurlOptions curlOptions)
    {
        System.Security.Cryptography.X509Certificates.X509Certificate2 pem;
        string keyPemFilePath = null;
        if (curlOptions.HasKey)
            keyPemFilePath = curlOptions.KeyFileName;

        if (curlOptions.HasCertificatePassword)
            pem = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromEncryptedPemFile(curlOptions.CertificateFileName, curlOptions.CertificatePassword, keyPemFilePath);
        else
            pem = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(curlOptions.CertificateFileName, keyPemFilePath);

        var bytes = pem.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx);

        var x2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(bytes);
        return x2;
    }


    private System.Security.Cryptography.X509Certificates.X509Certificate CreateP12Certificate(CurlOptions curlOptions)
    {
        System.Security.Cryptography.X509Certificates.X509Certificate2 p12;

        if (curlOptions.HasCertificatePassword)
            p12 = new System.Security.Cryptography.X509Certificates.X509Certificate2(curlOptions.CertificateFileName, curlOptions.CertificatePassword);
        else
            p12 = new System.Security.Cryptography.X509Certificates.X509Certificate2(curlOptions.CertificateFileName);
        return p12;
    }


    #endregion

    private void SetHeaderAssignment(HttpRequestMessage request, CurlOptions curlOptions)
    {
        if (!curlOptions.HasHeaders && !curlOptions.HasCookies)
            return;
        foreach (var header in curlOptions.Headers)
        {
            if (string.Equals(header.Key, HeaderNames.ContentType, StringComparison.InvariantCultureIgnoreCase))
                continue;
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        if (curlOptions.HasCookies)
        {
            request.Headers.TryAddWithoutValidation("Cookie", curlOptions.CookieValue);
        }
    }

    private void SetBasicAuthorization(HttpRequestMessage request, CurlOptions curlOptions)
    {
        if (string.IsNullOrEmpty(curlOptions.UserPasswordPair))
            return;
        var base64authorization = Convert.ToBase64String(Encoding.ASCII.GetBytes(curlOptions.UserPasswordPair));
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {base64authorization}");

    }


    #region 设置Content

    private List<HttpRequestMessage> GetUploadFileRequests(CurlOptions curlOptions)
    {
        var rs = new List<HttpRequestMessage>();
        foreach (var file in curlOptions.UploadFiles)
        {
            string requestUri;
            // NOTE that you must use a trailing / on the last directory to really prove to
            // Curl that there is no file name or curl will think that your last directory name is the remote file name to use.
            // example: curl -X POST --upload-file {file1.txt,file2.txt} https://example.com/upload/ -b SessionId=437b27169b6b4349a388038329eeb900 -H 'Referer: https://github.com/'
            if (!string.IsNullOrEmpty(curlOptions.Url.PathAndQuery) && curlOptions.Url.PathAndQuery.EndsWith('/'))
                //设置新的Url
                requestUri = curlOptions.GetUrlForFileUpload(file).ToString();
            else
                requestUri = curlOptions.GetFullUrl();

            var request = new HttpRequestMessage(new HttpMethod(curlOptions.HttpMethod), requestUri);
            SetHeaderAssignment(request, curlOptions);
            SetBasicAuthorization(request, curlOptions);
            request.Content = new ByteArrayContent(File.ReadAllBytes(file));
            rs.Add(request);
        }
        return rs;
    }

    private HttpRequestMessage GetSingleRequest(CurlOptions curlOptions)
    {
        var request = new HttpRequestMessage(new HttpMethod(curlOptions.HttpMethod), curlOptions.GetFullUrl());

        SetHeaderAssignment(request, curlOptions);
        SetBasicAuthorization(request, curlOptions);

        if (curlOptions.HasDataPayload && !curlOptions.ForceGet)
            CreateStringContentAssignment(request, curlOptions);
        else if (curlOptions.HasFormPayload)
            CreateMultipartContent(request, curlOptions);
        else if (curlOptions.HttpVersionSpecified)
            SetHttpVersion(request, curlOptions);
        return request;
    }

    /// <summary>
    /// 添加String类型的内容
    /// </summary>
    /// <param name="request"></param>
    /// <param name="curlOptions"></param>
    private void CreateStringContentAssignment(HttpRequestMessage request, CurlOptions curlOptions)
    {
        var contentList = new List<string>();
        foreach (var data in curlOptions.UploadData)
        {
            string kvalue = null;
            if (data.IsUrlEncoded)
            {
                if (data.IsFile)
                    kvalue = Uri.EscapeDataString(File.ReadAllText(data.Content));
                else
                    kvalue = Uri.EscapeDataString(data.Content);
                if (data.HasName)
                    kvalue = $"{data.Name}={kvalue}";
            }
            else if (data.Type == UploadDataType.BinaryFile)
            {
                kvalue = Uri.EscapeDataString(File.ReadAllText(data.Content));
            }
            else if (data.Type == UploadDataType.InlineFile)
            {
                kvalue = System.Text.RegularExpressions.Regex.Replace(kvalue, "(?:\\r\\n|\\n|\\r)", string.Empty);
            }
            if (!string.IsNullOrEmpty(kvalue))
                contentList.Add(kvalue);
        }

        request.Content = new StringContent(string.Join("&", contentList));
        request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(curlOptions.GetHeader(HeaderNames.ContentType));

    }

    private void CreateMultipartContent(HttpRequestMessage request, CurlOptions curlOptions)
    {
        var multipartContent = new MultipartFormDataContent();
        foreach (var data in curlOptions.FormData)
        {
            if (data.Type == UploadDataType.Inline)
                multipartContent.Add(new StringContent(data.Content), data.Name);
            else if (data.Type == UploadDataType.BinaryFile)
            {
                //文件名称
                var fileName = string.IsNullOrEmpty(data.FileName) ? Path.GetFileName(data.Content) : data.FileName;
                var fileByteArray = new ByteArrayContent(File.ReadAllBytes(fileName));

                // TODO 确认一下是否是多个
                //multipartContent.Add(new ByteArrayContent(File.ReadAllBytes("D:\\cv.pdf")), "cv", Path.GetFileName("D:\\cv.pdf"));

                if (!string.IsNullOrEmpty(data.ContentType))
                    fileByteArray.Headers.Add(HeaderNames.ContentType, data.ContentType);
                multipartContent.Add(fileByteArray);
            }
            else
                multipartContent.Add(new StringContent(File.ReadAllText(data.Content)), data.Name);
        }
        request.Content = multipartContent;
    }

    /// <summary>
    /// 设置http版本号
    /// </summary>
    /// <param name="request"></param>
    /// <param name="curlOptions"></param>
    private void SetHttpVersion(HttpRequestMessage request, CurlOptions curlOptions)
    {
        //设置http版本号
        switch (curlOptions.HttpVersion)
        {
            case Models.HttpVersion.Http09:
                request.Version = new Version(0, 9);
                break;
            case Models.HttpVersion.Http10:
                request.Version = new Version(1, 0);
                break;
            case Models.HttpVersion.Http11:
                request.Version = new Version(1, 1);
                break;
            case Models.HttpVersion.Http20:
                request.Version = new Version(2, 0);
                break;
            case Models.HttpVersion.Http30:
                request.Version = new Version(3, 0);
                break;
        }
    }

    #endregion

    #region 一些判断帮助方法


    private bool ShouldGenerateHandler(CurlOptions curlOptions)
    {
        return curlOptions.HasCookies
                || (curlOptions.HasProxy && IsSupportedProxy(curlOptions.ProxyUri))
                || (curlOptions.HasCertificate && IsSupportedCertificate(curlOptions.CertificateType))
                || curlOptions.Insecure
                || curlOptions.IsCompressed;
    }

    private bool ShouldNewHttpClient(CurlOptions curlOptions)
    {
        return (curlOptions.HasProxy && IsSupportedProxy(curlOptions.ProxyUri))
                || (curlOptions.HasCertificate && IsSupportedCertificate(curlOptions.CertificateType));
    }


    private bool IsSupportedProxy(Uri proxyUri)
    {
        return Uri.UriSchemeHttp == proxyUri.Scheme || Uri.UriSchemeHttps == proxyUri.Scheme;
    }


    private bool IsSupportedCertificate(CertificateType certificateType)
    {
        return certificateType is CertificateType.P12 or CertificateType.Pem;
    }

    private bool IsSupportedKey(KeyType keyType)
    {
        return keyType is KeyType.Pem;
    }

    #endregion


}
