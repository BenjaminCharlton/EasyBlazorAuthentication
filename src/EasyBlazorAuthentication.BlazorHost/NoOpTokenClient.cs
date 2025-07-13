using EasyBlazorAuthentication.HttpContracts;

namespace EasyBlazorAuthentication.BlazorHost;

internal class NoOpTokenClient : ISecurityTokenClient
{
    public async Task<bool> AcquireAndStoreTokenAsync()
    {
        return await Task.FromResult(false);
    }

    public async Task<string?> GetTokenAsync()
    {
        return await Task.FromResult(string.Empty);
    }

    public async Task ClearTokenAsync()
    {
        await Task.CompletedTask;
    }
}
