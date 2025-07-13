namespace EasyBlazorAuthentication.HttpContracts;
public record LogoutRequest
{
    public string? ReturnUrl { get; set; }
}
