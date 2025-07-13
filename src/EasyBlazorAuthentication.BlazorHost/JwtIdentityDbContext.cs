using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace EasyBlazorAuthentication.BlazorHost;

public class JwtIdentityDbContext(DbContextOptions options) : JwtIdentityDbContext<IdentityUser>(options)
{
}

public class JwtIdentityDbContext<TUser>(DbContextOptions options)
    : IdentityDbContext<TUser>(options)
    where TUser : IdentityUser
{
    public DbSet<RefreshToken<TUser>> RefreshTokens { get; set; }
}