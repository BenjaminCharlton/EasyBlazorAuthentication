namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Represents a response containing an access token and its expiration time.
/// </summary>
/// <remarks>This record is typically used to encapsulate the result of an authentication request, providing both
/// the access token and the time at which it expires.</remarks>
public record AccessTokenResponse
{
    /// <summary>
    /// Gets or sets the authentication token used for accessing secure resources.
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expiration date and time for the item.
    /// </summary>
    public DateTimeOffset Expires { get; set; }
}