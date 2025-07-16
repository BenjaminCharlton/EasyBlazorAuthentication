namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Provides constants for API endpoint paths used in authentication operations.
/// </summary>
/// <remarks>This class contains string constants representing the paths for various authentication-related API
/// endpoints. These constants can be used to ensure consistency and avoid hardcoding endpoint paths throughout the
/// application.</remarks>
public static class ApiEndpoints
{
    /// <summary>
    /// Represents the endpoint for generating a JSON Web Token (JWT).
    /// </summary>
    public const string GenerateJwt = "/generate-jwt";

    /// <summary>
    /// Represents the endpoint path for refreshing an authentication token.
    /// </summary>
    public const string RefreshToken = "/refresh-token";

    /// <summary>
    /// Represents the endpoint for logging out of the application.
    /// </summary>
    public const string Logout = "/logout";
}
