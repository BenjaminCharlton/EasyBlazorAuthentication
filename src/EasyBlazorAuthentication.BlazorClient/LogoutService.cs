namespace EasyBlazorAuthentication.BlazorClient;
public sealed class LogoutService(
    ISecurityTokenClient tokenClient,
    NavigationManager navigationManager,
    AntiforgeryStateProvider antiforgeryStateProvider,
    HttpClient httpClient)
{
    private readonly ISecurityTokenClient _tokenClient = tokenClient ?? throw new ArgumentNullException(nameof(tokenClient));
    private readonly NavigationManager _navigationManager = navigationManager ?? throw new ArgumentNullException(nameof(navigationManager));
    private readonly AntiforgeryStateProvider _antiforgeryStateProvider = antiforgeryStateProvider ?? throw new ArgumentNullException(nameof(antiforgeryStateProvider))
;
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    public async Task LogoutAsync()
    {
        var antiForgeryToken = _antiforgeryStateProvider.GetAntiforgeryToken()
            ?? throw new InvalidOperationException("Can't read anti-forgery token.");

        await _tokenClient.ClearTokenAsync();

        var relativeReturnUrl = _navigationManager.ToBaseRelativePath(_navigationManager.Uri);
        if (!relativeReturnUrl.StartsWith('/'))
        {
            relativeReturnUrl = "/" + relativeReturnUrl;
        }

        var request = new LogoutRequest
        {
            ReturnUrl = relativeReturnUrl
        };

        var requestMessage = new HttpRequestMessage(HttpMethod.Post, ApiEndpoints.Logout)
        {
            Content = JsonContent.Create(request)
        };

        requestMessage.Headers.Add(HeaderNames.Antiforgery, antiForgeryToken.Value);

        var response = await _httpClient.SendAsync(requestMessage);

        if (response.IsSuccessStatusCode)
        {
            var redirect = await response.Content.ReadFromJsonAsync<RedirectResponse>();
            _navigationManager.NavigateTo(redirect?.RedirectUrl ?? "/", forceLoad: true);
            return;
        }

        _navigationManager.NavigateTo("/", forceLoad: true);
    }
}