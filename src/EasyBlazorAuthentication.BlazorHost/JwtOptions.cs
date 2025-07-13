namespace EasyBlazorAuthentication.BlazorHost;

internal sealed class JwtOptions
{
    public const string SectionName = "Jwt";
    public string Key { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string Audience { get; init; } = "";
    public int AccessTokenLifetimeMinutes { get; init; } = 60;
    public int RefreshTokenLifetimeDays { get; init; } = 7;
}
