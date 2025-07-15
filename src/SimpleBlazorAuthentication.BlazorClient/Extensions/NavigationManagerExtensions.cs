namespace Microsoft.AspNetCore.Components;

public static class NavigationManagerExtensions
{
    public static void NavigateTo(
        this NavigationManager nav,
        string uri,
        IReadOnlyDictionary<string, object?> query,
        bool forceLoad = false,
        bool replace = false)
    {
        var absolute = nav.ToAbsoluteUri(uri).GetLeftPart(UriPartial.Path);
        var full = nav.GetUriWithQueryParameters(absolute, query);
        nav.NavigateTo(full, forceLoad, replace);
    }
}