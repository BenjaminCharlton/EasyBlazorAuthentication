using System.ComponentModel.DataAnnotations;

namespace SimpleBlazorAuthentication.BlazorHost.Configuration;

public class MicrosoftAccountAuthenticationOptions : IValidatableObject
{
    public bool IsEnabled { get; set; } = false;

    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (IsEnabled)
        {
            if (string.IsNullOrWhiteSpace(ClientId))
            {
                yield return new ValidationResult("Microsoft Account ClientId is required when Microsoft Account authentication is enabled.", [nameof(ClientId)]);
            }

            if (string.IsNullOrWhiteSpace(ClientSecret))
            {
                yield return new ValidationResult("Microsoft Account ClientSecret is required when Microsoft Account authentication is enabled.", [nameof(ClientSecret)]);
            }
        }
    }
}