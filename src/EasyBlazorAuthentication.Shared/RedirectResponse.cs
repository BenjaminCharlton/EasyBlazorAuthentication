namespace EasyBlazorAuthentication.HttpContracts;

public record RedirectResponse
{
    public string RedirectUrl { get; set; } = "/";
}