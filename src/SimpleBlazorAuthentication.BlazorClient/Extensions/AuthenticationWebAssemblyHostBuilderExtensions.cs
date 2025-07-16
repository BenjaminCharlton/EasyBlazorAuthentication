namespace Microsoft.AspNetCore.Components.WebAssembly.Hosting;

/// <summary>
/// Provides extension methods for configuring authentication in a Blazor WebAssembly application.
/// </summary>
/// <remarks>This class includes methods to add authentication services to a <see cref="WebAssemblyHostBuilder"/>.
/// It supports configuring authentication with default or custom user information types and integrates with local
/// storage and JWT handling.</remarks>
public static class AuthenticationWebAssemblyHostBuilderExtensions
{
    /// <summary>
    /// Configures authentication services for a Blazor WebAssembly application. Adds application authentication to the specified
    /// <see cref="WebAssemblyHostBuilder"/> instance.
    /// </summary>
    /// <remarks>This method configures authentication using a default user information type, mapping user ID
    /// and email to claims. It sets up local storage, token management, and authentication state management
    /// services necessary for handling user authentication in a Blazor WebAssembly application. It also registers the
    /// required services for authorization and cascading authentication state.</remarks>
    /// <param name="builder">The <see cref="WebAssemblyHostBuilder"/> to which authentication is added.</param>
    /// <returns>The <see cref="WebAssemblyHostBuilder"/> with authentication configured.</returns>
    public static WebAssemblyHostBuilder AddApplicationAuthentication(
    this WebAssemblyHostBuilder builder)
    {
        return builder.AddApplicationAuthentication<DefaultUserInfo>(userInfo =>
        {
            return [
                new Claim(ClaimTypes.NameIdentifier, userInfo.UserId),
                new Claim(ClaimTypes.Name, userInfo.Email),
                new Claim(ClaimTypes.Email, userInfo.Email)
                ];
        });
    }

    /// <summary>
    /// Configures authentication services for a Blazor WebAssembly application. Adds application authentication to the specified
    /// <see cref="WebAssemblyHostBuilder"/> instance.
    /// </summary>
    /// <remarks>This method configures authentication using the user type passed. It sets up local storage, token management, and authentication state management
    /// services necessary for handling user authentication in a Blazor WebAssembly application. It also registers the
    /// required services for authorization and cascading authentication state.</remarks>
    /// <typeparam name="TUserInfo">The type representing user information.</typeparam>
    /// <param name="builder">The <see cref="WebAssemblyHostBuilder"/> to configure.</param>
    /// <param name="claimsFactory">A function that extracts a collection of <see cref="Claim"/> objects from a user information instance.</param>
    /// <returns>The configured <see cref="WebAssemblyHostBuilder"/> instance.</returns>
    public static WebAssemblyHostBuilder AddApplicationAuthentication<TUserInfo>(
        this WebAssemblyHostBuilder builder,
        Func<TUserInfo, IEnumerable<Claim>> claimsFactory)
    {
        builder.Services.AddBlazoredLocalStorage();
        builder.Services.AddScoped<ISecurityTokenClient, JwtClient>();
        builder.Services.AddScoped<ILogoutService, ClientLogoutService>();

        builder.Services.AddSingleton<AuthenticationStateProvider>(sp =>
        new PersistentAuthenticationStateProvider<TUserInfo>(
            sp.GetRequiredService<PersistentComponentState>(),
            claimsFactory));

        builder.Services.AddAuthorizationCore();
        builder.Services.AddCascadingAuthenticationState();

        return builder;
    }
}