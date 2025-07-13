namespace Microsoft.Extensions.DependencyInjection;

internal sealed class JwtAuthenticationMessageHandler(ISecurityTokenClient tokenClient) : DelegatingHandler
{
    private readonly ISecurityTokenClient _tokenClient = tokenClient ?? throw new ArgumentNullException(nameof(tokenClient));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokenClient.GetTokenAsync();
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}