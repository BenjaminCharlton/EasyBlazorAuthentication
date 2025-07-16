using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SimpleBlazorAuthentication.BlazorClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SimpleBlazorAuthentication.BlazorHost;

internal sealed class JwtService<TUser, TDbContext>(
    UserManager<TUser> userManager,
    TDbContext db,
    IOptions<JwtOptions> jwtOptions,
    IHttpContextAccessor httpContextAccessor) : JwtService<TUser, string, TDbContext>(userManager, db, jwtOptions, httpContextAccessor)
    where TUser : IdentityUser
    where TDbContext : IJwtDbContext
{
}

internal class JwtService<TUser, TKey, TDbContext>(
UserManager<TUser> userManager,
TDbContext db,
IOptions<JwtOptions> jwtOptions,
IHttpContextAccessor httpContextAccessor) : IAuthTokenService
where TUser : IdentityUser<TKey>
where TKey : IEquatable<TKey>
where TDbContext : IJwtDbContext
{
    private readonly UserManager<TUser> _users = userManager ?? throw new ArgumentNullException(nameof(userManager));
    private readonly TDbContext _db = db ?? throw new ArgumentNullException(nameof(db));
    private readonly JwtOptions _jwtOptions = jwtOptions.Value ?? throw new ArgumentNullException(nameof(jwtOptions));
    private readonly IHttpContextAccessor _http = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));

    public async Task<AccessTokenResponse> IssueAsync(ClaimsPrincipal principal)
    {
        var user = await _users.GetUserAsync(principal) ?? throw new();
        var refresh = NewRefreshToken(user.Id);

        _db.RefreshTokens.Add(refresh);
        await _db.SaveChangesAsync();

        SetRefreshCookie(refresh);

        return new AccessTokenResponse
        {
            Token = BuildJwt(user.Id, user.UserName),
            Expires = refresh.Expires
        };
    }

    public async Task<AccessTokenResponse?> RefreshAsync(string token)
    {
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
        if (stored is null || stored.Expires <= DateTimeOffset.UtcNow || stored.Revoked)
        {
            return null;
        }

        stored.Revoked = true;

        var user = await _users.FindByIdAsync(stored.UserId) ?? throw new();
        var fresh = NewRefreshToken(user.Id);

        _db.RefreshTokens.Add(fresh);
        await _db.SaveChangesAsync();

        SetRefreshCookie(fresh);

        return new AccessTokenResponse
        {
            Token = BuildJwt(user.Id, user.UserName),
            Expires = fresh.Expires
        };
    }

    public async Task RevokeAsync(string token)
    {
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
        if (stored is not null)
        {
            stored.Revoked = true;
        }

        await _db.SaveChangesAsync();
        DeleteRefreshCookie();
    }

    private RefreshToken NewRefreshToken(TKey userId, int size = 64)
    {
        var bytes = new byte[size];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);

        return new RefreshToken
        {
            UserId = userId.ToString()!,
            Token = Convert.ToBase64String(bytes),
            Created = DateTimeOffset.UtcNow,
            Expires = DateTimeOffset.UtcNow.AddDays(_jwtOptions.RefreshTokenLifetimeDays)
        };
    }

    private string BuildJwt(TKey userId, string? userName)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()!),
            new Claim(JwtRegisteredClaimNames.UniqueName, userName ?? "")
        };

        var token = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtOptions.AccessTokenLifetimeMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private void SetRefreshCookie(RefreshToken refreshToken)
    {
        _http.HttpContext!.Response.Cookies.Delete(
            CookieNames.RefreshToken,
            AuthCookieOptions.Delete);

        _http.HttpContext!.Response.Cookies.Append(
            CookieNames.RefreshToken,
            refreshToken.Token,
            AuthCookieOptions.Issue(refreshToken.Expires));
    }

    private void DeleteRefreshCookie() =>
        _http.HttpContext!.Response.Cookies.Delete(
            CookieNames.RefreshToken,
            AuthCookieOptions.Delete);

    private static class AuthCookieOptions
    {
        public static CookieOptions Issue(DateTimeOffset expires) => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = ApiEndpoints.RefreshToken,
            Expires = expires.UtcDateTime
        };

        /// <summary>Options for deleting the cookie.</summary>
        public static readonly CookieOptions Delete = new()
        {
            Path = ApiEndpoints.RefreshToken,
            Secure = true,
            SameSite = SameSiteMode.Strict
        };
    }
}
