namespace SimpleBlazorAuthentication.BlazorClient;

internal sealed class JwtClient(HttpClient httpClient, ILocalStorageService localStorage, AntiforgeryStateProvider antiForgery) : ISecurityTokenClient
{
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly ILocalStorageService _localStorage = localStorage ?? throw new ArgumentNullException(nameof(localStorage));
    private readonly AntiforgeryStateProvider _antiForgery = antiForgery ?? throw new ArgumentNullException(nameof(antiForgery));

    private const string _tokenKey = "jwt";
    private const string _expiryKey = "jwt_expiry";

    public async Task<string?> GetTokenAsync()
    {
        var token = await _localStorage.GetItemAsync<string>(_tokenKey);
        var expiry = await _localStorage.GetItemAsync<DateTime>(_expiryKey);

        if (!string.IsNullOrEmpty(token) && expiry > DateTime.UtcNow.AddSeconds(30))
        {
            return token;
        }

        // Token missing/near expiry – try silent refresh
        if (await TryRefreshAsync())
        {
            return await _localStorage.GetItemAsync<string>(_tokenKey);
        }

        await ClearTokenAsync(); // nothing worked – force re-auth
        return null;
    }

    public async Task ClearTokenAsync()
    {
        await _localStorage.RemoveItemAsync(_tokenKey);
        await _localStorage.RemoveItemAsync(_expiryKey);
    }

    public async Task<bool> AcquireAndStoreTokenAsync()
         => await CallTokenEndpointAsync(ApiEndpoints.GenerateJwt);

    private async Task<bool> TryRefreshAsync()
     => await CallTokenEndpointAsync(ApiEndpoints.RefreshToken);

    private async Task<bool> CallTokenEndpointAsync(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, url);
        if (_antiForgery.GetAntiforgeryToken() is AntiforgeryRequestToken xsrfToken)
        {
            req.Headers.Add(HeaderNames.Antiforgery, [xsrfToken.Value]);
        }

        var rsp = await _httpClient.SendAsync(req);
        if (!rsp.IsSuccessStatusCode)
        {
            return false;
        }

        var payload = await rsp.Content.ReadFromJsonAsync<AccessTokenResponse>();
        if (payload is null || string.IsNullOrWhiteSpace(payload.Token))
        {
            return false;
        }

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(payload.Token);

        await _localStorage.SetItemAsync(_tokenKey, payload.Token);
        await _localStorage.SetItemAsync(_expiryKey, jwt.ValidTo);
        return true;
    }
}