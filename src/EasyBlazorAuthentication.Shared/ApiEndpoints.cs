namespace EasyBlazorAuthentication.HttpContracts;

public static class ApiEndpoints
{
    public const string GenerateJwt = "/generate-jwt";
    public const string RefreshToken = "/refresh-token";
    public const string Logout = "/logout";
    public const string PerformExternalLogin = "/perform-external-login";
    public const string LinkExternalLogin = "/link-external-login";
    public const string DownloadPersonalData = "/download-personal-data";
}
