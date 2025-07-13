using EasyBlazorAuthentication.BlazorHost;
using EasyBlazorAuthentication.HttpContracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Routing;

public static class AuthenticationEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints<TUser>(this IEndpointRouteBuilder app)
        where TUser : class
    {
        var auth = app.MapGroup(string.Empty)
                      .AddEndpointFilter<AntiforgeryFilter>()
                      .WithTags(nameof(EasyBlazorAuthentication));

        auth.MapPost(ApiEndpoints.GenerateJwt, GenerateJwtAsync)
            .RequireAuthorization();

        auth.MapPost(ApiEndpoints.RefreshToken, RefreshTokenAsync);

        auth.MapPost(ApiEndpoints.Logout, LogoutAsync<TUser>);

        return auth;
    }

    private static async Task<IResult> GenerateJwtAsync(
        ClaimsPrincipal user,
        IAuthTokenService authTokenService)
    {
        var token = await authTokenService.IssueAsync(user);
        return Results.Ok(token);
    }

    private static async Task<IResult> RefreshTokenAsync(
        HttpContext context,
        IAuthTokenService authTokenService)
    {
        var cookie = context.Request.Cookies[CookieNames.RefreshToken];
        if (string.IsNullOrEmpty(cookie))
        {
            return Results.Unauthorized();
        }

        var resp = await authTokenService.RefreshAsync(cookie);
        return resp is null ? Results.Unauthorized() : Results.Ok(resp);
    }

    private static async Task<IResult> LogoutAsync<TUser>(
    [FromBody] LogoutRequest request,
    HttpContext context,
    SignInManager<TUser> signIn,
    IAuthTokenService tokens)
        where TUser : class
    {
        var returnUrl = string.IsNullOrWhiteSpace(request.ReturnUrl) ||
                        !Uri.IsWellFormedUriString(request.ReturnUrl, UriKind.Relative) ||
                        !request.ReturnUrl.StartsWith('/')
                        ? "/"
                        : request.ReturnUrl;

        var refreshCookie = context.Request.Cookies[CookieNames.RefreshToken];

        if (!string.IsNullOrEmpty(refreshCookie))
        {
            await tokens.RevokeAsync(refreshCookie);
        }

        await signIn.SignOutAsync();

        return Results.Ok(new RedirectResponse { RedirectUrl = returnUrl });
    }
}