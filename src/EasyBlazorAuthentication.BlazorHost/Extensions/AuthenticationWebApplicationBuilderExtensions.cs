using EasyBlazorAuthentication.BlazorHost;
using EasyBlazorAuthentication.HttpContracts;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Builder;

public static class AuthenticationWebApplicationBuilderExtensions
{
    public static WebApplicationBuilder AddApplicationAuthentication<TDbContext, TUser, TEmailSender>(
        this WebApplicationBuilder builder)
        where TUser : IdentityUser
        where TDbContext : JwtIdentityDbContext<TUser>
        where TEmailSender : class, IEmailSender<TUser>
    {
        return builder.AddApplicationAuthentication<TDbContext, TUser, DefaultUserInfo, TEmailSender>((principal, options) =>
        {
            var userId = principal.FindFirst(options.ClaimsIdentity.UserIdClaimType)?.Value;
            var email = principal.FindFirst(options.ClaimsIdentity.EmailClaimType)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                throw new InvalidOperationException("Authenticated user is missing required UserId claim.");
            }

            if (string.IsNullOrEmpty(email))
            {
                throw new InvalidOperationException("Authenticated user is missing required Email claim.");
            }

            return new DefaultUserInfo
            {
                UserId = userId,
                Email = email,
            };
        });
    }

    public static WebApplicationBuilder AddApplicationAuthentication<TDbContext, TUser, TUserInfo, TEmailSender>(
        this WebApplicationBuilder builder,
        Func<ClaimsPrincipal, IdentityOptions, TUserInfo?> userInfoFactory)
        where TUser : IdentityUser
        where TDbContext : JwtIdentityDbContext<TUser>
        where TEmailSender : class, IEmailSender<TUser>
    {
        builder.AddAntiforgerySupport();
        builder.AddJwtAuthentication<TUser, TDbContext>();
        builder.AddIdentityInfrastructure<TUser, TDbContext, TEmailSender>();
        builder.ConfigureAuthenticationCookies();
        builder.Services.AddScoped<AuthenticationStateProvider, PersistingRevalidatingAuthenticationStateProvider<TUser, TUserInfo>>();

        builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
        new PersistingRevalidatingAuthenticationStateProvider<TUser, TUserInfo>(
            sp.GetRequiredService<ILoggerFactory>(),
            sp.GetRequiredService<IServiceScopeFactory>(),
            sp.GetRequiredService<PersistentComponentState>(),
            sp.GetRequiredService<IOptions<IdentityOptions>>(),
            userInfoFactory));

        return builder;
    }

    private static WebApplicationBuilder AddAntiforgerySupport(this WebApplicationBuilder builder)
    {
        builder.Services.AddAntiforgery(o =>
        {
            o.HeaderName = HeaderNames.Antiforgery;
        });

        return builder;
    }

    private static WebApplicationBuilder AddJwtAuthentication<TUser, TDbContext>(this WebApplicationBuilder builder)
        where TUser : IdentityUser
        where TDbContext : JwtIdentityDbContext<TUser>
    {
        builder.Services.AddOptions<JwtOptions>()
                .Bind(builder.Configuration.GetSection(JwtOptions.SectionName));

        builder.Services.AddScoped<IAuthTokenService, JwtService<TUser, TDbContext>>();

        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddScoped<ISecurityTokenClient, NoOpTokenClient>();
        return builder;
    }

    private static WebApplicationBuilder AddIdentityInfrastructure<TUser, TDbContext, TEmailSender>(this WebApplicationBuilder builder)
        where TUser : IdentityUser
        where TDbContext : JwtIdentityDbContext<TUser>
        where TEmailSender : class, IEmailSender<TUser>
    {
        builder.Services.AddIdentityCore<TUser>(options => options.SignIn.RequireConfirmedAccount = true)
            .AddEntityFrameworkStores<TDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = IdentityConstants.ApplicationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        })
    .AddIdentityCookies();

        return builder;
    }

    private static WebApplicationBuilder ConfigureAuthenticationCookies(this WebApplicationBuilder builder)
    {
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Events.OnRedirectToLogin = context =>
            {
                // Return 401 for API requests instead of redirecting
                if (context.Request.Path.StartsWithSegments(ApiEndpoints.GenerateJwt) ||
                    context.Request.Headers.Accept == "application/json")
                {
                    return Results.Unauthorized()
                                  .ExecuteAsync(context.HttpContext);
                }

                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            };
        });

        return builder;
    }
}