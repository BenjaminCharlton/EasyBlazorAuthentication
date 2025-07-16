namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Defines a service for handling user logout operations.
/// </summary>
/// <remarks>Implementations of this interface should provide the necessary logic to log a user out of the system,
/// such as clearing authentication tokens or session data. It is intended that there will be separate implementations
/// for Blazor Server and Blazor WebAssembly.</remarks>
public interface ILogoutService
{
    /// <summary>
    /// Logs the user out asynchronously, terminating the current session.
    /// </summary>
    /// <remarks>This method clears the user's authentication state and any associated session data. It should
    /// be called when the user chooses to log out or when the application needs to end the session.</remarks>
    /// <returns>A task that represents the asynchronous logout operation.</returns>
    Task LogoutAsync();
}
