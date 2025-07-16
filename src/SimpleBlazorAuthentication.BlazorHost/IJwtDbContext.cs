using Microsoft.EntityFrameworkCore;

namespace SimpleBlazorAuthentication.BlazorHost;

/// <summary>
/// Represents a database context for managing JWT-related data, specifically refresh tokens.
/// </summary>
/// <remarks>This interface defines the contract for a database context that handles the storage and retrieval of
/// refresh tokens. Implementations of this interface are responsible for providing access to the underlying data store
/// where refresh tokens are persisted.</remarks>
public interface IJwtDbContext
{
    /// <summary>
    /// Gets or sets the collection of refresh tokens stored in the database.
    /// </summary>
    DbSet<RefreshToken> RefreshTokens { get; set; }

    /// <summary>
    /// Saves all changes made in this context to the database asynchronously.
    /// </summary>
    Task SaveChangesAsync();
}