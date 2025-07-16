namespace SimpleBlazorAuthentication.BlazorClient;

internal sealed class PersistentAuthenticationStateProvider<TUserInfo> : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> _defaultUnauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    private readonly Task<AuthenticationState> _authenticationStateTask = _defaultUnauthenticatedTask;

    public PersistentAuthenticationStateProvider(PersistentComponentState state,
        Func<TUserInfo, IEnumerable<Claim>> claimsFactory)
    {
        if (!state.TryTakeFromJson<TUserInfo>(typeof(TUserInfo).Name, out var userInfo) || userInfo is null)
        {
            return;
        }

        var claims = claimsFactory(userInfo);

        _authenticationStateTask = Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims,
                authenticationType: nameof(PersistentAuthenticationStateProvider<TUserInfo>)))));
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync() => _authenticationStateTask;
}
