
namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Defines methods for acquiring, retrieving, and clearing security tokens.
/// </summary>
/// <remarks>Implementations of this interface are responsible for managing the lifecycle of security tokens,
/// including acquiring new tokens, retrieving stored tokens, and clearing tokens when they are no longer
/// needed.  It is intended that there will be separate implementations
/// for Blazor Server and Blazor WebAssembly.</remarks>
public interface ISecurityTokenClient
{
    /// <summary>
    /// Asynchronously acquires an authentication token and stores it securely.
    /// </summary>
    /// <remarks>This method attempts to obtain a new authentication token and store it for future use. It
    /// handles any necessary authentication flows and ensures the token is stored securely.</remarks>
    /// <returns><see langword="true"/> if the token was successfully acquired and stored; otherwise, <see langword="false"/>.</returns>
    Task<bool> AcquireAndStoreTokenAsync();

    /// <summary>
    /// Asynchronously retrieves an authentication token.
    /// </summary>
    /// <returns>A task representing the asynchronous operation. The task result contains the authentication token as a string,
    /// or <see langword="null"/> if the token could not be retrieved.</returns>
    Task<string?> GetTokenAsync();

    /// <summary>
    /// Asynchronously clears the stored authentication token.
    /// </summary>
    /// <remarks>This method removes any existing authentication token from storage, effectively logging the
    /// user out. It should be called when the user wishes to terminate their session or when the token is no longer
    /// valid.</remarks>
    Task ClearTokenAsync();
}