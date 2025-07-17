using System.ComponentModel.DataAnnotations;

namespace SimpleBlazorAuthentication.BlazorHost.Configuration;

public class AuthenticationOptions : IValidatableObject
{
    public const string Position = "Authentication";
    public GoogleAuthenticationOptions Google { get; set; } = new();
    public FacebookAuthenticationOptions Facebook { get; set; } = new();
    public MicrosoftAccountAuthenticationOptions MicrosoftAccount { get; set; } = new();
    public TwitterAuthenticationOptions Twitter { get; set; } = new();

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var results = new List<ValidationResult>();

        Validator.TryValidateObject(Google, new ValidationContext(Google), results, true);
        Validator.TryValidateObject(Facebook, new ValidationContext(Facebook), results, true);
        Validator.TryValidateObject(MicrosoftAccount, new ValidationContext(MicrosoftAccount), results, true);
        Validator.TryValidateObject(Twitter, new ValidationContext(Twitter), results, true);

        return results;
    }
}
