using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder;

public static class AuthenticationWebApplicationExtensions
{
    public static WebApplication UseApplicationAuthentication<TUser>(this WebApplication app)
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