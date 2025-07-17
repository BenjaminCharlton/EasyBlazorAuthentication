using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SimpleBlazorAuthentication.BlazorClient;
using SimpleBlazorAuthentication.BlazorHost;
using SimpleBlazorAuthentication.BlazorHost.Configuration;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Provides extension methods for configuring authentication services in a <see cref="WebApplicationBuilder"/>.
/// </summary>
/// <remarks>This class includes methods to add simple authentication using JWT and Identity, configure
/// antiforgery support, and set up authentication state management. It supports customization through generic
/// parameters for user, role, and email sender types, as well as a user info factory function.</remarks>
public static class AuthenticationWebApplicationBuilderExtensions
{
    /// <summary>
    /// Configures authentication for the application using the specified email sender, database context, user info, and user types
    /// and the default type for sharing user information between the Blazor host and Blazor client apps.
    /// </summary>
    /// <remarks>This method sets up authentication services using JWT tokens and configures the application
    /// to use the specified types for user management.</remarks>
    /// <typeparam name="TDbContext">The type of the database context used for identity operations.</typeparam>
    /// <typeparam name="TUser">The type representing a user in the identity system.</typeparam>
    /// <typeparam name="TUserInfo">The type representing user information shared between a Blazor WebAssembly application and its host.</typeparam>
    /// <typeparam name="TEmailSender">The type responsible for sending emails.</typeparam>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The configured <see cref="WebApplicationBuilder"/> instance.</returns>
    public static WebApplicationBuilder AddSimpleAuthentication<TEmailSender, TDbContext, TUser>(
        this WebApplicationBuilder builder)
        where TEmailSender : class, IEmailSender<TUser>
        where TDbContext : IdentityDbContext<TUser, IdentityRole<string>, string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityRoleClaim<string>, IdentityUserToken<string>>, IJwtDbContext
        where TUser : IdentityUser<string>
    {
        return builder.AddSimpleAuthentication<TEmailSender, TDbContext, DefaultUserInfo, TUser>(
            CreateDefaultUserInfo);
    }


    /// <summary>
    /// Configures authentication for the application using the specified email sender, database context, user info, and user types.
    /// </summary>
    /// <remarks>This method sets up authentication services using JWT tokens and configures the application
    /// to use the specified types for user management.</remarks>
    /// <typeparam name="TDbContext">The type of the database context used for identity operations.</typeparam>
    /// <typeparam name="TUser">The type representing a user in the identity system.</typeparam>
    /// <typeparam name="TUserInfo">The type representing user information shared between a Blazor WebAssembly application and its host.</typeparam>
    /// <typeparam name="TEmailSender">The type responsible for sending emails.</typeparam>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <param name="userInfoFactory">A factory function to create an instance of <typeparamref name="TUserInfo"/> from a <see
    /// cref="ClaimsPrincipal"/> and <see cref="IdentityOptions"/>.</param>
    /// <returns>The configured <see cref="WebApplicationBuilder"/> instance.</returns>
    public static WebApplicationBuilder AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser>(
        this WebApplicationBuilder builder,
        Func<ClaimsPrincipal, IdentityOptions, TUserInfo?> userInfoFactory)
        where TEmailSender : class, IEmailSender<TUser>
        where TDbContext : IdentityDbContext<TUser, IdentityRole<string>, string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityRoleClaim<string>, IdentityUserToken<string>>, IJwtDbContext
        where TUser : IdentityUser<string>
    {
        return builder.AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser, IdentityRole<string>, string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityRoleClaim<string>, IdentityUserToken<string>>(
            userInfoFactory);
    }

    /// <summary>
    /// Configures authentication for the application using the specified email sender, database context, user info, user, and key types.
    /// </summary>
    /// <remarks>This method sets up authentication services using JWT tokens and configures the application
    /// to use the specified types for user management.</remarks>
    /// <typeparam name="TDbContext">The type of the database context used for identity operations.</typeparam>
    /// <typeparam name="TUser">The type representing a user in the identity system.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
    /// <typeparam name="TUserInfo">The type representing user information shared between a Blazor WebAssembly application and its host.</typeparam>
    /// <typeparam name="TEmailSender">The type responsible for sending emails.</typeparam>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <param name="userInfoFactory">A factory function to create an instance of <typeparamref name="TUserInfo"/> from a <see
    /// cref="ClaimsPrincipal"/> and <see cref="IdentityOptions"/>.</param>
    /// <returns>The configured <see cref="WebApplicationBuilder"/> instance.</returns>
    public static WebApplicationBuilder AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser, TKey>(
        this WebApplicationBuilder builder,
        Func<ClaimsPrincipal, IdentityOptions, TUserInfo?> userInfoFactory)
        where TEmailSender : class, IEmailSender<TUser>
        where TDbContext : IdentityDbContext<TUser, IdentityRole<TKey>, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>, IJwtDbContext
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        return builder.AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser, IdentityRole<TKey>, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>(
            userInfoFactory);
    }

    /// <summary>
    /// Configures authentication for the application using the specified email sender, database context, user info, user, key, and role types.
    /// </summary>
    /// <remarks>This method sets up authentication services using JWT tokens and configures the application
    /// to use the specified types for user management.</remarks>
    /// <typeparam name="TDbContext">The type of the database context used for identity operations.</typeparam>
    /// <typeparam name="TUser">The type representing a user in the identity system.</typeparam>
    /// <typeparam name="TUserInfo">The type representing user information shared between a Blazor WebAssembly application and its host.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
    /// <typeparam name="TEmailSender">The type responsible for sending emails.</typeparam>
    /// <typeparam name="TRole">The type of role objects.</typeparam>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <param name="userInfoFactory">A factory function to create an instance of <typeparamref name="TUserInfo"/> from a <see
    /// cref="ClaimsPrincipal"/> and <see cref="IdentityOptions"/>.</param>
    /// <returns>The configured <see cref="WebApplicationBuilder"/> instance.</returns>
    public static WebApplicationBuilder AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser, TRole, TKey>(
        this WebApplicationBuilder builder,
        Func<ClaimsPrincipal, IdentityOptions, TUserInfo?> userInfoFactory)
        where TEmailSender : class, IEmailSender<TUser>
        where TDbContext : IdentityDbContext<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>, IJwtDbContext
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TRole : IdentityRole<TKey>
    {
        return builder.AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>(
            userInfoFactory);
    }


    /// <summary>
    /// Configures authentication for the application using the specified email sender, database context, user info, user, key, user claim, role,
    /// user role, user login, role claim and user token types.
    /// </summary>
    /// <remarks>This method sets up authentication services using JWT tokens and configures the application
    /// to use the specified types for user management.</remarks>
    /// <typeparam name="TDbContext">The type of the database context used for identity operations.</typeparam>
    /// <typeparam name="TUser">The type representing a user in the identity system.</typeparam>
    /// <typeparam name="TUserInfo">The type representing user information shared between a Blazor WebAssembly application and its host.</typeparam>
    /// <typeparam name="TEmailSender">The type responsible for sending emails.</typeparam>
    /// <typeparam name="TRole">The type of role objects.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
    /// <typeparam name="TRoleClaim">The type representing a role claim, inheriting from <see cref="IdentityRoleClaim{TKey}"/>.</typeparam>
    /// <typeparam name="TUserClaim">The type representing a user claim, inheriting from <see cref="IdentityUserClaim{TKey}"/>.</typeparam>
    /// <typeparam name="TUserLogin">The type representing a user login, inheriting from <see cref="IdentityUserLogin{TKey}"/>.</typeparam>
    /// <typeparam name="TUserRole">The type representing the relationship between users and roles, typically inheriting from <see cref="IdentityUserRole{TKey}"/>.</typeparam>
    /// <typeparam name="TUserToken">The type representing a user token, inheriting from <see cref="IdentityUserToken{TKey}"/>.</typeparam>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <param name="userInfoFactory">A factory function to create an instance of <typeparamref name="TUserInfo"/> from a <see
    /// cref="ClaimsPrincipal"/> and <see cref="IdentityOptions"/>.</param>
    /// <returns>The configured <see cref="WebApplicationBuilder"/> instance.</returns>
    public static WebApplicationBuilder AddSimpleAuthentication<TEmailSender, TDbContext, TUserInfo, TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>(
        this WebApplicationBuilder builder,
        Func<ClaimsPrincipal, IdentityOptions, TUserInfo?> userInfoFactory)
        where TEmailSender : class, IEmailSender<TUser>
        where TDbContext : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>, IJwtDbContext
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TRole : IdentityRole<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TRoleClaim : IdentityRoleClaim<TKey>
        where TUserToken : IdentityUserToken<TKey>
    {
        builder.Services.AddSingleton<TEmailSender, TEmailSender>();
        builder.Services.Configure<SimpleBlazorAuthentication.BlazorHost.Configuration.AuthenticationOptions>(
            builder.Configuration.GetSection(SimpleBlazorAuthentication.BlazorHost.Configuration.AuthenticationOptions.Position));

        builder.AddAntiforgerySupport();
        builder.AddJwtAuthentication<TUser, TKey, TDbContext>();
        builder.Services.ConfigureIdentityCore<TUser, TDbContext>();

        builder.Services.ConfigureAuthentication(builder.Configuration);
        builder.ConfigureAuthenticationCookies();

        builder.Services.AddScoped<ILogoutService, HostLogoutService<TUser>>();

        builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
        new PersistingRevalidatingAuthenticationStateProvider<TUser, TUserInfo>(
            sp.GetRequiredService<ILoggerFactory>(),
            sp.GetRequiredService<IServiceScopeFactory>(),
            sp.GetRequiredService<PersistentComponentState>(),
            sp.GetRequiredService<IOptions<IdentityOptions>>(),
            userInfoFactory));

        return builder;
    }

    private static DefaultUserInfo CreateDefaultUserInfo(ClaimsPrincipal principal, IdentityOptions options)
    {
        if (!TryGetClaim(principal, options.ClaimsIdentity.UserIdClaimType, out var userId))
        {
            throw new InvalidOperationException("Authenticated user is missing required UserId claim.");
        }

        if (!TryGetClaim(principal, options.ClaimsIdentity.EmailClaimType, out var email))
        {
            throw new InvalidOperationException("Authenticated user is missing required Email claim.");
        }

        return new DefaultUserInfo
        {
            UserId = userId,
            Email = email,
        };
    }

    private static bool TryGetClaim(ClaimsPrincipal principal, string claimType, out string value)
    {
        value = principal.Claims.FirstOrDefault(c => c.Type == claimType)?.Value ?? string.Empty;
        return !string.IsNullOrEmpty(value);
    }

    private static WebApplicationBuilder AddAntiforgerySupport(this WebApplicationBuilder builder)
    {
        builder.Services.AddAntiforgery(o =>
        {
            o.HeaderName = HeaderNames.Antiforgery;
        });

        return builder;
    }

    private static WebApplicationBuilder AddJwtAuthentication<TUser, TKey, TDbContext>(this WebApplicationBuilder builder)
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TDbContext : IJwtDbContext
    {
        builder.Services.AddOptions<JwtOptions>()
                .Bind(builder.Configuration.GetSection(JwtOptions.SectionName));

        builder.Services.AddScoped<IAuthTokenService, JwtService<TUser, TKey, TDbContext>>();

        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddScoped<ISecurityTokenClient, NoOpTokenClient>();
        return builder;
    }

    private static IdentityBuilder ConfigureIdentityCore<TUser, TDbContext>(this IServiceCollection services)
        where TUser : class
        where TDbContext : DbContext
    {
        return services.AddIdentityCore<TUser>(options => options.SignIn.RequireConfirmedAccount = true)
            .AddEntityFrameworkStores<TDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();
    }

    private static IServiceCollection ConfigureAuthentication(this IServiceCollection services, ConfigurationManager configuration)
    {
        services.ConfigureLocalAuthentication()
            .ConfigureThirdPartyAuthentication(configuration);

        return services;
    }

    private static AuthenticationBuilder ConfigureLocalAuthentication(this IServiceCollection services)
    {
        var authBuilder = services.AddAuthentication(options =>
        {
            options.DefaultScheme = IdentityConstants.ApplicationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        });

        authBuilder.AddIdentityCookies();

        return authBuilder;
    }

    private static WebApplicationBuilder ConfigureAuthenticationCookies(this WebApplicationBuilder builder)
    {
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Events.OnRedirectToLogin = context =>
            {
                // Return 401 for API requests instead of redirecting
                if (context.Request.Path.StartsWithSegments(ApiEndpoints.GenerateJwt) ||
                    context.Request.Headers.Accept.Contains("application/json"))
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