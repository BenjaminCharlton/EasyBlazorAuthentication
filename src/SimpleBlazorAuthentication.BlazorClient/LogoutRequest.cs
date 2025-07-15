namespace SimpleBlazorAuthentication.BlazorClient;
public record LogoutRequest
{
    public string? ReturnUrl { get; set; }
}
