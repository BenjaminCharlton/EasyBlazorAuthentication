using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Authentication;

internal static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder ConfigureThirdPartyAuthentication(this AuthenticationBuilder builder, ConfigurationManager configuration)
    {
        var authOptions = new SimpleBlazorAuthentication.BlazorHost.Configuration.AuthenticationOptions();
        configuration.GetSection(SimpleBlazorAuthentication.BlazorHost.Configuration.AuthenticationOptions.Position).Bind(authOptions);

        if (authOptions.Google.IsEnabled)
        {
            builder.AddGoogle(options =>
            {
                options.ClientId = authOptions.Google.ClientId;
                options.ClientSecret = authOptions.Google.ClientSecret;
            });
        }

        if (authOptions.Facebook.IsEnabled)
        {
            builder.AddFacebook(options =>
            {
                options.ClientId = authOptions.Facebook.AppId;
                options.ClientSecret = authOptions.Facebook.AppSecret;
            });
        }

        if (authOptions.MicrosoftAccount.IsEnabled)
        {
            builder.AddMicrosoftAccount(options =>
            {
                options.ClientId = authOptions.MicrosoftAccount.ClientId;
                options.ClientSecret = authOptions.MicrosoftAccount.ClientSecret;
            });
        }

        if (authOptions.Twitter.IsEnabled)
        {
            builder.AddTwitter(options =>
            {
                options.ConsumerKey = authOptions.Twitter.ConsumerKey;
                options.ConsumerSecret = authOptions.Twitter.ConsumerSecret;
            });
        }

        return builder;
    }
}