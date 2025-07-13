using EasyBlazorAuthentication.HttpContracts;
using System.Security.Claims;

namespace EasyBlazorAuthentication.BlazorHost;

internal interface IAuthTokenService
{
    Task<AccessTokenResponse> IssueAsync(ClaimsPrincipal user);
    Task<AccessTokenResponse?> RefreshAsync(string refreshToken);
    Task RevokeAsync(string refreshToken);
}
