namespace SimpleBlazorAuthentication.BlazorClient;

public record AccessTokenResponse
{
    public string Token { get; set; } = string.Empty;
    public DateTimeOffset Expires { get; set; }
}