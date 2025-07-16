namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Provides extension methods for adding HTTP clients with authentication capabilities to an <see
/// cref="IServiceCollection"/>.
/// </summary>
/// <remarks>This static class contains methods to register HTTP clients with optional JWT authentication
/// handlers. It allows for the configuration of typed clients with specified base addresses, facilitating the
/// integration of authenticated and anonymous HTTP requests within an application.</remarks>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Adds an authenticated HTTP client to the service collection with a specified base address.
    /// </summary>
    /// <remarks>This method registers a scoped <see cref="JwtAuthenticationMessageHandler"/> to handle JWT
    /// authentication for the HTTP client. The client is configured to use the specified base address and is set up to
    /// include the authentication handler in the HTTP request pipeline.</remarks>
    /// <typeparam name="TClient">The type of the client interface.</typeparam>
    /// <typeparam name="TImplementation">The type of the client implementation.</typeparam>
    /// <param name="services">The service collection to which the HTTP client is added.</param>
    /// <param name="baseAddress">The base address for the HTTP client.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to further configure the HTTP client.</returns>
    public static IHttpClientBuilder AddAuthenticatedApiHttpClient<TClient, TImplementation>(this IServiceCollection services, string baseAddress)
        where TClient : class
        where TImplementation : class, TClient
    {
        services.AddScoped<JwtAuthenticationMessageHandler>();

        return services.AddAnonymousApiHttpClient<TClient, TImplementation>(baseAddress)
            .AddHttpMessageHandler<JwtAuthenticationMessageHandler>();
    }

    /// <summary>
    /// Adds an HTTP client for the specified typed client and implementation with a base address.
    /// </summary>
    /// <remarks>This method registers an HTTP client with a specified base address, allowing for typed client
    /// usage. The client is configured to use the provided base address for all requests.</remarks>
    /// <typeparam name="TClient">The type of the client interface to register.</typeparam>
    /// <typeparam name="TImplementation">The type of the concrete implementation to use for the client.</typeparam>
    /// <param name="services">The service collection to which the HTTP client is added.</param>
    /// <param name="baseAddress">The base address for the HTTP client. Must be a valid URI.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to configure the client.</returns>
    public static IHttpClientBuilder AddAnonymousApiHttpClient<TClient, TImplementation>(this IServiceCollection services, string baseAddress)
        where TClient : class
        where TImplementation : class, TClient
    {
        return services.AddHttpClient<TClient, TImplementation>(client => client.BaseAddress = new Uri(baseAddress));
    }
}