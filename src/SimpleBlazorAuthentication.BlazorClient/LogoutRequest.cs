namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Represents a request to log out a user, optionally specifying a URL to redirect to after logout.
/// </summary>
/// <remarks>This request can include a return URL, which is used to redirect the user after the logout process is
/// completed. If no return URL is specified, the default post-logout behavior will be applied.</remarks>
public record LogoutRequest
{
    /// <summary>
    /// Gets or sets the URL to which the user is redirected after a successful operation.
    /// </summary>
    public string? ReturnUrl { get; set; }
}
