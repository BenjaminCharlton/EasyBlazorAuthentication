
namespace EasyBlazorAuthentication.HttpContracts;

public interface ISecurityTokenClient
{
    Task<bool> AcquireAndStoreTokenAsync();
    Task<string?> GetTokenAsync();
    Task ClearTokenAsync();
}