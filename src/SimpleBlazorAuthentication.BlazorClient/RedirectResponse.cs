namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Represents a response that contains a URL to which a client should be redirected.
/// </summary>
/// <remarks>This record is typically used in scenarios where a client needs to be redirected to a different URL,
/// such as after a successful login or when accessing a resource that has moved.</remarks>
public record RedirectResponse
{
    /// <summary>
    /// Gets or sets the URL to which the user is redirected.
    /// </summary>
    public string RedirectUrl { get; set; } = "/";
}