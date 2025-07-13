namespace EasyBlazorAuthentication.HttpContracts;

public static class ClientRoutes
{
    public static class Account
    {
        private const string _root = "/Account";
        public const string RedirectAfterLogin = $"{_root}/RedirectAfterLogin";
    }
}