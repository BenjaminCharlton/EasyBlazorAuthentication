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
    : JwtIdentityDbContext<TUser, string>(options)
    where TUser : IdentityUser
{ }

/// <summary>
/// Represents a database context for managing identity and authentication using JWT tokens.
/// </summary>
/// <remarks>This context extends <see cref="IdentityDbContext{TUser}"/> to include functionality for handling
/// refresh tokens, which are stored in the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <typeparam name="TUser">The type of user entity, which must inherit from <see cref="IdentityUser"/>.</typeparam>
/// <typeparam name="TRole">The type representing a role in the identity system, inheriting from <see cref="IdentityRole{TKey}"/>.</typeparam>
/// <typeparam name="TKey">The type of the primary key for users and roles, such as <c>string</c> or <c>Guid</c>.</typeparam>
/// <remarks>This context is configured to work with ASP.NET Core Identity and JWT authentication. It provides the
/// necessary infrastructure to manage user identities, roles, and claims within a database. It extends 
/// <see cref="IdentityDbContext{TUser}"/> to include functionality for handling refresh tokens, which are stored in
/// the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <param name="options">The options to be used by a <see cref="DbContext" /></param>
public class JwtIdentityDbContext<TUser, TKey>(DbContextOptions options)
    : JwtIdentityDbContext<TUser, IdentityRole<TKey>, TKey>(options)
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{ }

/// <summary>
/// Represents a database context for managing identity and authentication using JWT tokens.
/// </summary>
/// <remarks>This context extends <see cref="IdentityDbContext{TUser}"/> to include functionality for handling
/// refresh tokens, which are stored in the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <typeparam name="TUser">The type of user entity, which must inherit from <see cref="IdentityUser"/>.</typeparam>
/// <typeparam name="TRole">The type representing a role in the identity system, inheriting from <see cref="IdentityRole{TKey}"/>.</typeparam>
/// <typeparam name="TKey">The type of the primary key for users and roles, such as <c>string</c> or <c>Guid</c>.</typeparam>
/// <remarks>This context is configured to work with ASP.NET Core Identity and JWT authentication. It provides the
/// necessary infrastructure to manage user identities, roles, and claims within a database. It extends 
/// <see cref="IdentityDbContext{TUser}"/> to include functionality for handling refresh tokens, which are stored in
/// the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <param name="options">The options to be used by a <see cref="DbContext" /></param>
public class JwtIdentityDbContext<TUser, TRole, TKey>(DbContextOptions options)
    : JwtIdentityDbContext<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>(options)
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
    where TRole : IdentityRole<TKey>
{ }

/// <summary>
/// Represents a database context for managing identity and authentication using JWT tokens.
/// </summary>
/// <remarks>This context extends <see cref="IdentityDbContext{TUser}"/> to include functionality for handling
/// refresh tokens, which are stored in the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <typeparam name="TUser">The type of user entity, which must inherit from <see cref="IdentityUser"/>.</typeparam>
/// <typeparam name="TRole">The type representing a role in the identity system, inheriting from <see cref="IdentityRole{TKey}"/>.</typeparam>
/// <typeparam name="TKey">The type of the primary key for users and roles, such as <c>string</c> or <c>Guid</c>.</typeparam>
/// <typeparam name="TUserClaim">The type representing a user claim, inheriting from <see cref="IdentityUserClaim{TKey}"/>.</typeparam>
/// <typeparam name="TUserRole">The type representing the relationship between users and roles, typically inheriting from <see cref="IdentityUserRole{TKey}"/>.</typeparam>
/// <typeparam name="TUserLogin">The type representing a user login, inheriting from <see cref="IdentityUserLogin{TKey}"/>.</typeparam>
/// <typeparam name="TRoleClaim">The type representing a role claim, inheriting from <see cref="IdentityRoleClaim{TKey}"/>.</typeparam>
/// <typeparam name="TUserToken">The type representing a user token, inheriting from <see cref="IdentityUserToken{TKey}"/>.</typeparam>
/// <remarks>This context is configured to work with ASP.NET Core Identity and JWT authentication. It provides the
/// necessary infrastructure to manage user identities, roles, and claims within a database. It extends 
/// <see cref="IdentityDbContext{TUser}"/> to include functionality for handling refresh tokens, which are stored in
/// the <see cref="RefreshTokens"/> DbSet.</remarks>
/// <param name="options">The options to be used by a <see cref="DbContext" /></param>
public class JwtIdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>(DbContextOptions options)
    : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>(options), IJwtDbContext
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>
    where TRole : IdentityRole<TKey>
    where TUserRole : IdentityUserRole<TKey>
    where TUserLogin : IdentityUserLogin<TKey>
    where TRoleClaim : IdentityRoleClaim<TKey>
    where TUserToken : IdentityUserToken<TKey>
{
    /// <summary>
    /// Gets or sets the collection of refresh tokens stored in the database.
    /// </summary>
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    /// <summary>
    /// Saves all changes made in this context to the database.
    /// </summary>
    /// <param name="cancellationToken">
    /// A <see cref="System.Threading.CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous save operation. The task result contains the number of state entries written to the database.
    /// </returns>
    /// <exception cref="Microsoft.EntityFrameworkCore.DbUpdateException">
    /// An error is encountered while saving to the database.
    /// </exception>
    /// <exception cref="Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException">
    /// A concurrency violation is encountered while saving to the database. A concurrency violation occurs when an unexpected number of rows are affected during save. This is usually because the data in the database has been modified since it was loaded into memory.
    /// </exception>
    /// <exception cref="System.OperationCanceledException">
    /// If the <see cref="System.Threading.CancellationToken"/> is canceled.
    /// </exception>
    /// <remarks>
    /// This method will automatically call <see cref="Microsoft.EntityFrameworkCore.ChangeTracking.ChangeTracker.DetectChanges"/> to discover any changes to entity instances before saving to the underlying database.
    /// This can be disabled via <see cref="Microsoft.EntityFrameworkCore.ChangeTracking.ChangeTracker.AutoDetectChangesEnabled"/>.
    /// <para>
    /// Entity Framework Core does not support multiple parallel operations being run on the same <see cref="DbContext"/> instance. This includes both parallel execution of async queries and any explicit concurrent use from multiple threads. Therefore, always await async calls immediately, or use separate <see cref="DbContext"/> instances for operations that execute in parallel. See <b>Avoiding DbContext threading issues</b> for more information and examples.
    /// </para>
    /// <para>
    /// See <b>Saving data in EF Core</b> for more information and examples.
    /// </para>
    /// </remarks>
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await base.SaveChangesAsync(cancellationToken);
    }
    public async Task SaveChangesAsync()
    {
        await base.SaveChangesAsync();
    }
}