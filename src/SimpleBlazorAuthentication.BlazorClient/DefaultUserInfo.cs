namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Represents the default user information that is shared between the Blazor host and Blazor client apps.
/// </summary>
public sealed class DefaultUserInfo
{
    /// <summary>
    /// Gets or sets the unique identifier for the user in the ASP .NET Core Identity database.
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// Gets or sets the email address associated with the user.
    /// </summary>
    public required string Email { get; set; }
}
