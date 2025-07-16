using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SimpleBlazorAuthentication.BlazorHost;

/// <summary>
/// Represents a database context for managing identity and authentication using JWT tokens.
/// </summary>
/// <remarks>This context is configured to work with ASP.NET Core Identity and JWT authentication. It provides the
/// necessary infrastructure to manage user identities, roles, and claims within a database. It extends 
/// <see cref="IdentityDbContext{TUser}"/> to include functionality for handling refresh tokens, which are stored in
/// the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <param name="options">The options to be used by a <see cref="DbContext" /></param>
public class JwtIdentityDbContext(DbContextOptions options) : JwtIdentityDbContext<IdentityUser>(options)
{
}

/// <summary>
/// Represents a database context for managing identity and authentication using JWT tokens.
/// </summary>
/// <remarks>This context extends <see cref="IdentityDbContext{TUser}"/> to include functionality for handling
/// refresh tokens, which are stored in the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <typeparam name="TUser">The type of user entity, which must inherit from <see cref="IdentityUser"/>.</typeparam>
/// <remarks>This context is configured to work with ASP.NET Core Identity and JWT authentication. It provides the
/// necessary infrastructure to manage user identities, roles, and claims within a database. It extends 
/// <see cref="IdentityDbContext{TUser}"/> to include functionality for handling refresh tokens, which are stored in
/// the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <param name="options">The options to be used by a <see cref="DbContext" /></param>
public class JwtIdentityDbContext<TUser>(DbContextOptions options)
    : IdentityDbContext<TUser>(options)
    where TUser : IdentityUser
{
    /// <summary>
    /// Gets or sets the collection of refresh tokens associated with users.
    /// </summary>
    public DbSet<RefreshToken<TUser>> RefreshTokens { get; set; }
}