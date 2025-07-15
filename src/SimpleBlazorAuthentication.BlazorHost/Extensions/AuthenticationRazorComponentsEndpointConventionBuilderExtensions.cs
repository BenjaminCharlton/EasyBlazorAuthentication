using SimpleBlazorAuthentication.BlazorClient;

namespace Microsoft.AspNetCore.Builder;

public static class AuthenticationRazorComponentsEndpointConventionBuilderExtensions
{
    public static RazorComponentsEndpointConventionBuilder AddAuthenticationComponents(
    this RazorComponentsEndpointConventionBuilder builder)
    {
        return builder.AddAdditionalAssemblies(typeof(_Imports).Assembly);
    }
}