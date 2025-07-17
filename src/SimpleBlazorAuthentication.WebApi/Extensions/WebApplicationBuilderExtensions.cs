using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Microsoft.AspNetCore.Builder;

public static class WebApplicationBuilderExtensions
{
    private static readonly string[] _defaultAllowedMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
    private static readonly string[] _defaultWithHeaders = ["X-Requested-With", "Authorization", "Content-Type", "Accept", "Origin"];
    private const string _jwtAudienceKey = "Jwt:Audience";
    private const string _jwtAudiencesKey = "Jwt:Audiences";
    private const string _jwtKeyKey = "Jwt:Key";
    private const string _jwtIssuerKey = "Jwt:Issuer";

    public static WebApplicationBuilder ConfigureSimpleCors(
        this WebApplicationBuilder builder,
        IEnumerable<string> allowedOrigins,
        IEnumerable<string>? allowedMethods = null,
        IEnumerable<string>? withHeaders = null,
        bool allowCredentials = true)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (allowedOrigins is null || !allowedOrigins.Any())
        {
            throw new ArgumentException("At least one allowed origin must be specified.", nameof(allowedOrigins));
        }

        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.WithOrigins([.. allowedOrigins]);
                policy.WithMethods([.. allowedMethods ?? _defaultAllowedMethods]);
                policy.WithHeaders([.. withHeaders ?? _defaultWithHeaders]);
                if (allowCredentials)
                {
                    policy.AllowCredentials();
                }
            });
        });

        return builder;
    }

    public static WebApplicationBuilder ConfigureSimpleAuthentication(this WebApplicationBuilder builder, string? jwtIssuer = null, params string[] audiences)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (audiences is null || audiences.Length == 0)
        {
            audiences = TryGetAudiencesFromConfiguration(builder.Configuration);
        }

        if (audiences.Length == 0)
        {
            throw new InvalidOperationException($"At least one audience must be specified in application configuration or passed to the {nameof(ConfigureSimpleAuthentication)} method.");
        }

        if (string.IsNullOrEmpty(jwtIssuer))
        {
            jwtIssuer ??= builder.Configuration[_jwtIssuerKey];
        }

        if (string.IsNullOrEmpty(jwtIssuer))
        {
            throw new InvalidOperationException($"JWT issuer (authority) must be specified in application configuration or passed to the {nameof(ConfigureSimpleAuthentication)} method.");
        }

        var jwtKey = builder.Configuration[_jwtKeyKey] ?? throw new InvalidOperationException("JWT key must be specified in application configuration.");

        builder.Services.AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = jwtIssuer;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtIssuer,
                    ValidateAudience = true,
                    ValidAudiences = audiences,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
                };

                options.Events = new Authentication.JwtBearer.JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.Response.ContentType = "application/json";
                        var problemDetails = new ProblemDetails
                        {
                            Status = StatusCodes.Status401Unauthorized,
                            Title = "Unauthorized",
                            Detail = "Not Authenticated"
                        };
                        var result = System.Text.Json.JsonSerializer.Serialize(problemDetails);
                        return context.Response.WriteAsync(result);
                    },
                    OnForbidden = context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        context.Response.ContentType = "application/json";
                        var problemDetails = new ProblemDetails
                        {
                            Status = StatusCodes.Status403Forbidden,
                            Title = "Forbidden",
                            Detail = "Forbidden"
                        };
                        var result = System.Text.Json.JsonSerializer.Serialize(problemDetails);
                        return context.Response.WriteAsync(result);
                    }
                };
            });

        return builder;
    }

    private static string[] TryGetAudiencesFromConfiguration(ConfigurationManager config)
    {

        string audience = config[_jwtAudienceKey] ?? string.Empty;
        string[] audiences = config.GetSection(_jwtAudiencesKey).Get<string[]>() ?? [];

        if (!string.IsNullOrEmpty(audience) && audiences is not null && audiences.Length > 0)
        {
            throw new InvalidOperationException($"Only one of {_jwtAudienceKey} and {_jwtAudiencesKey} can be specified in application configuration. Not both.");
        }

        return audiences?.Length == 0 ? [audience] : audiences ?? [];
    }
}
