namespace SimpleBlazorAuthentication.BlazorHost;

/// <summary>
/// Represents a refresh token associated with a user, used for authentication and session management.
/// </summary>
/// <remarks>A refresh token is typically used to obtain a new access token without requiring the user to
/// re-authenticate. This record includes information about the token's expiration, revocation status, and the user it
/// is associated with.</remarks>
/// <typeparam name="TUser">The type of the user associated with the refresh token.</typeparam>
public record RefreshToken
{
    /// <summary>
    /// Gets or sets the unique identifier for the entity.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier for the user.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the authentication token used for accessing secured resources.
    /// </summary>
    public string Token { get; set; } = default!;

    /// <summary>
    /// Gets or sets the expiration date and time for the token.
    /// </summary>
    public DateTimeOffset Expires { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the item has been revoked prior to expiry.
    /// </summary>
    public bool Revoked { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the entity was created.
    /// </summary>
    public DateTimeOffset Created { get; set; }
}