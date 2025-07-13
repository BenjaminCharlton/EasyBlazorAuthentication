namespace Microsoft.AspNetCore.Components.WebAssembly.Hosting;

public static class AuthenticationWebAssemblyHostBuilderExtensions
{
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

    public static WebAssemblyHostBuilder AddApplicationAuthentication<TUserInfo>(
        this WebAssemblyHostBuilder builder,
        Func<TUserInfo, IEnumerable<Claim>> claimsFactory)
    {
        builder.Services.AddBlazoredLocalStorage();
        builder.Services.AddScoped<ISecurityTokenClient, JwtClient>();

        builder.Services.AddSingleton<AuthenticationStateProvider>(sp =>
        new PersistentAuthenticationStateProvider<TUserInfo>(
            sp.GetRequiredService<PersistentComponentState>(),
            claimsFactory));

        builder.Services.AddAuthorizationCore();
        builder.Services.AddCascadingAuthenticationState();

        return builder;
    }
}