namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Provides a collection of standard HTTP header names used in web applications.
/// </summary>
/// <remarks>This class contains constants representing common HTTP header names, which can be used to ensure
/// consistency and avoid typos when working with headers in HTTP requests and responses.</remarks>
internal static class HeaderNames
{
    /// <summary>
    /// The HTTP header name of the antiforgery token used for request verification.
    /// </summary>
    public const string Antiforgery = "RequestVerificationToken";
}
