using SimpleBlazorAuthentication.BlazorClient;
using System.Security.Claims;

namespace SimpleBlazorAuthentication.BlazorHost;

internal interface IAuthTokenService
{
    Task<AccessTokenResponse> IssueAsync(ClaimsPrincipal user);
    Task<AccessTokenResponse?> RefreshAsync(string refreshToken);
    Task RevokeAsync(string refreshToken);
}
