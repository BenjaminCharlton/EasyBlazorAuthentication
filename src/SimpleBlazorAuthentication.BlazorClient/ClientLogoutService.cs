namespace SimpleBlazorAuthentication.BlazorClient;

/// <summary>
/// Provides functionality for a Blazor WebAssembly client to log out a client from the application, clearing security tokens and navigating to a
/// specified return URL.
/// </summary>
/// <remarks>This service handles the logout process by clearing the security token, sending a logout request to
/// the server, and navigating to a return URL. It ensures that an anti-forgery token is included in the logout request
/// for security purposes.</remarks>
/// <param name="tokenClient">An <see cref="ISecurityTokenClient"/> for clearing tokens from storage.</param>
/// <param name="navigationManager">A <see cref="NavigationManager"/> to redirect the user after a successful logout.</param>
/// <param name="antiforgeryStateProvider">A <see cref="AntiforgeryStateProvider" /> to provide an anti-forgery token to the server's logout endpoint.</param>
/// <param name="httpClient">An <see cref="HttpClient" /> to call the server's logout endpoint.</param>
public sealed class ClientLogoutService(
    ISecurityTokenClient tokenClient,
    NavigationManager navigationManager,
    AntiforgeryStateProvider antiforgeryStateProvider,
    HttpClient httpClient) : ILogoutService
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