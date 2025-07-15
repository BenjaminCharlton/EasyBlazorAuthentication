namespace SimpleBlazorAuthentication.BlazorHost;

public record RefreshToken<TUser> where TUser : class
{
    public int Id { get; set; }
    public string UserId { get; set; } = default!;
    public string Token { get; set; } = default!;
    public DateTimeOffset Expires { get; set; }
    public bool Revoked { get; set; }
    public DateTimeOffset Created { get; set; }
    public TUser User { get; set; } = default!;
}