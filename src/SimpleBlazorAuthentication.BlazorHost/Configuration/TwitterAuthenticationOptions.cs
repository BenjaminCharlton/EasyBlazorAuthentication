using System.ComponentModel.DataAnnotations;

namespace SimpleBlazorAuthentication.BlazorHost.Configuration;

public class TwitterAuthenticationOptions : IValidatableObject
{
    public bool IsEnabled { get; set; } = false;

    public string ConsumerKey { get; set; } = string.Empty;
    public string ConsumerSecret { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (IsEnabled)
        {
            if (string.IsNullOrWhiteSpace(ConsumerKey))
            {
                yield return new ValidationResult("Twitter ConsumerKey is required when Twitter authentication is enabled.", [nameof(ConsumerKey)]);
            }

            if (string.IsNullOrWhiteSpace(ConsumerSecret))
            {
                yield return new ValidationResult("Twitter ConsumerSecret is required when Twitter authentication is enabled.", [nameof(ConsumerSecret)]);
            }
        }
    }
}
