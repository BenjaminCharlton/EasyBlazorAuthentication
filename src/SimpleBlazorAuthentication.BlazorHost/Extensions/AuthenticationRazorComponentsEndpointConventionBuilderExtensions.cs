using SimpleBlazorAuthentication.BlazorClient;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Provides extension methods for configuring authentication components in Razor Components endpoints.
/// </summary>
public static class AuthenticationRazorComponentsEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Adds authentication components to the specified Razor components endpoint convention builder.
    /// </summary>
    /// <param name="builder">The <see cref="RazorComponentsEndpointConventionBuilder"/> to which authentication components are added.</param>
    /// <returns>The <see cref="RazorComponentsEndpointConventionBuilder"/> with authentication components added.</returns>
    public static RazorComponentsEndpointConventionBuilder AddAuthenticationComponents(
    this RazorComponentsEndpointConventionBuilder builder)
    {
        return builder.AddAdditionalAssemblies(typeof(_Imports).Assembly);
    }
}