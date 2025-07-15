
namespace SimpleBlazorAuthentication.BlazorClient;

public interface ISecurityTokenClient
{
    Task<bool> AcquireAndStoreTokenAsync();
    Task<string?> GetTokenAsync();
    Task ClearTokenAsync();
}