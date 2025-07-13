using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace EasyBlazorAuthentication.BlazorHost;

internal class AntiforgeryFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var af = context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
        if (!await af.IsRequestValidAsync(context.HttpContext))
        {
            return MoreResults.InvalidAntiforgeryToken;
        }

        return await next(context);
    }
}