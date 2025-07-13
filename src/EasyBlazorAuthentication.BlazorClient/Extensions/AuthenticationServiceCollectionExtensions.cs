namespace Microsoft.Extensions.DependencyInjection;

public static class AuthenticationServiceCollectionExtensions
{
    public static IHttpClientBuilder AddAuthenticatedApiHttpClient<TClient, TImplementation>(this IServiceCollection services, string baseAddress)
        where TClient : class
        where TImplementation : class, TClient
    {
        services.AddScoped<JwtAuthenticationMessageHandler>();

        return services.AddAnonymousApiHttpClient<TClient, TImplementation>(baseAddress)
            .AddHttpMessageHandler<JwtAuthenticationMessageHandler>();
    }

    public static IHttpClientBuilder AddAnonymousApiHttpClient<TClient, TImplementation>(this IServiceCollection services, string baseAddress)
        where TClient : class
        where TImplementation : class, TClient
    {
        return services.AddHttpClient<TClient, TImplementation>(client => client.BaseAddress = new Uri(baseAddress));
    }
}