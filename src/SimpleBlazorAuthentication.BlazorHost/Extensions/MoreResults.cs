using System.Net;

namespace Microsoft.AspNetCore.Http;

/// <summary>
/// Additional possible results of type <see cref="IResult" /> to return from HTTP endpoints, that aren't included in Microsoft's <see cref="Results" />
/// </summary>
internal static class MoreResults
{
    public static IResult InvalidAntiforgeryToken =>
        Results.Problem("Antiforgery token was missing or not valid.", null, (int)HttpStatusCode.BadRequest, "Invalid antiforgery token");
}