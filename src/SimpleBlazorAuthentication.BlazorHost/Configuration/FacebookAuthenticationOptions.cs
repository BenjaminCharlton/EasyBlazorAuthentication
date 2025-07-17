using System.ComponentModel.DataAnnotations;

namespace SimpleBlazorAuthentication.BlazorHost.Configuration;

public class FacebookAuthenticationOptions : IValidatableObject
{
    public bool IsEnabled { get; set; } = false;

    public string AppId { get; set; } = string.Empty;
    public string AppSecret { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (IsEnabled)
        {
            if (string.IsNullOrWhiteSpace(AppId))
            {
                yield return new ValidationResult("Facebook AppId is required when Facebook authentication is enabled.", [nameof(AppId)]);
            }

            if (string.IsNullOrWhiteSpace(AppSecret))
            {
                yield return new ValidationResult("Facebook AppSecret is required when Facebook authentication is enabled.", [nameof(AppSecret)]);
            }
        }
    }
}
