namespace SimpleBlazorAuthentication.BlazorClient;

public record RedirectResponse
{
    public string RedirectUrl { get; set; } = "/";
}