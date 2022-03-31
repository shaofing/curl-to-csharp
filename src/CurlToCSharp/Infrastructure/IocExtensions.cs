using CurlToCSharp.Models;
using CurlToCSharp.Services;
using System.Text;

using Microsoft.Extensions.Options;

namespace CurlToCSharp.Infrastructure;

public static class IocExtensions
{
    public static void RegisterServices(this IServiceCollection services)
    {
        _IServiceCollection = services;
        //services.AddScoped(a => services);
        services.AddSingleton(
            provider => provider.GetService<IOptions<ApplicationOptions>>()
                .Value.Parsing);

        services.AddSingleton<ICommandLineParser, CommandLineParser>();
        services.AddSingleton<IConverterService, ConverterService>();
        services.AddSingleton<IConverterRequestService, ConverterRequestService>();
    }

    private static IServiceCollection _IServiceCollection;

    public static IServiceCollection GetRootServiceCollection()
    {
        return _IServiceCollection;
    }

    public static void AddHttpClientForQtMessageCurl(this IServiceCollection services)
    {
        /*
        bool HasCookies;    0b001
        bool IsCompressed;  0b010
        bool Insecure;      0b100
        */
        //3个布尔值，所以是2的3次方,一共注册8个
        var max = Math.Pow(2, 3);

        for (int i = 0; i < max; i++)
        {
            if (i > 0)
            {
                var handler = new HttpClientHandler();
                //HasCookies
                if (0b001 == (0b001 & i))
                    //这里设为false, 通过HttpRequestMessage 设置Cookie
                    handler.UseCookies = false;
                //IsCompressed
                if (0b010 == (0b010 & i))
                    handler.AutomaticDecompression = System.Net.DecompressionMethods.All;
                //Insecure
                if (0b100 == (0b100 & i))
                    handler.ServerCertificateCustomValidationCallback = (requestMessage, certificate, chain, policyErrors) => true;

                services.AddHttpClient($"{ConverterRequestService.HttpClientForQtMessageCurlPrefixName}{i}").ConfigurePrimaryHttpMessageHandler(_ =>
                {
                    return handler;
                });
            }
            else
                services.AddHttpClient($"{ConverterRequestService.HttpClientForQtMessageCurlPrefixName}{i}");
        }

    }


}
