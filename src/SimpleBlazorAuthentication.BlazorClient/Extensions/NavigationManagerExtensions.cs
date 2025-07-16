namespace Microsoft.AspNetCore.Components;

/// <summary>
/// Provides extension methods for the <see cref="NavigationManager"/> class to enhance navigation capabilities.
/// </summary>
public static class NavigationManagerExtensions
{
    /// <summary>
    /// Navigates to the specified URI with the given query parameters.
    /// </summary>
    /// <remarks>This method constructs a full URI by combining the specified base URI with the provided query
    /// parameters and then navigates to it.</remarks>
    /// <param name="nav">The <see cref="NavigationManager"/> used to perform the navigation.</param>
    /// <param name="uri">The base URI to navigate to. This must be a relative or absolute URI.</param>
    /// <param name="query">A dictionary containing query parameters to append to the URI. Keys represent parameter names, and values
    /// represent parameter values.</param>
    /// <param name="forceLoad"><see langword="true"/> to force the browser to load the new page from the server, bypassing client-side routing;
    /// otherwise, <see langword="false"/>.</param>
    /// <param name="replace"><see langword="true"/> to replace the current entry in the browser's history stack; otherwise, <see
    /// langword="false"/> to append a new entry.</param>
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