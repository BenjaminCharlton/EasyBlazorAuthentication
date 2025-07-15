using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using SimpleBlazorAuthentication.BlazorClient;

namespace SimpleBlazorAuthentication.BlazorHost;

internal sealed class HostLogoutService<TUser>(
    NavigationManager navigationManager,
    IHttpContextAccessor httpContextAccessor,
    SignInManager<TUser> signInManager,
    IAuthTokenService authTokenService) : ILogoutService
    where TUser : class
{
    private readonly NavigationManager _navigationManager = navigationManager ?? throw new ArgumentNullException(nameof(navigationManager));
    private readonly SignInManager<TUser> _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    private readonly IAuthTokenService _authTokenService = authTokenService ?? throw new ArgumentNullException(nameof(authTokenService));

    public async Task LogoutAsync()
    {
        var relativeReturnUrl = _navigationManager.ToBaseRelativePath(_navigationManager.Uri);
        if (!relativeReturnUrl.StartsWith('/'))
        {
            relativeReturnUrl = "/" + relativeReturnUrl;
        }

        var context = _httpContextAccessor.HttpContext;
        var refreshCookie = context?.Request.Cookies[CookieNames.RefreshToken];

        if (!string.IsNullOrEmpty(refreshCookie))
        {
            await _authTokenService.RevokeAsync(refreshCookie);
        }

        await _signInManager.SignOutAsync();

        _navigationManager.NavigateTo(relativeReturnUrl, forceLoad: true);
    }
}