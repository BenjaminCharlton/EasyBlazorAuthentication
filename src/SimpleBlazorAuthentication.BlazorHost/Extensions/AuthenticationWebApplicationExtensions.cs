using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Provides extension methods for configuring authentication services in a <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class AuthenticationWebApplicationExtensions
{
    /// <summary>
    /// Configures the application to use authentication with antiforgery protection and strict cookie policies.
    /// </summary>
    /// <remarks>This method sets up antiforgery protection and configures cookie policies to ensure secure
    /// handling of cookies. It also maps authentication endpoints.</remarks>
    /// <typeparam name="TUser">The type representing the user entity in the authentication process.</typeparam>
    /// <param name="app">The <see cref="WebApplication"/> instance to configure.</param>
    /// <returns>The configured <see cref="WebApplication"/> instance.</returns>
    public static WebApplication UseSimpleAuthentication<TUser>(this WebApplication app)
        where TUser : class
    {
        app.UseAntiforgery();

        app.UseCookiePolicy(new CookiePolicyOptions
        {
            Secure = CookieSecurePolicy.Always,
            MinimumSameSitePolicy = SameSiteMode.Strict
        });

        app.MapAuthenticationEndpoints<TUser>();

        return app;
    }
}