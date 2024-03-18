using BaseLibrary.Entities;
using Microsoft.EntityFrameworkCore;

namespace ServerLibrary.Data
{
	public class AppDbContext : DbContext
	{
		public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
		{

		}
		public DbSet<Employee> Employees { get; set; }
		public DbSet<GeneralDepartament> GeneralDepartaments { get; set; }
		public DbSet<Departament> Departaments { get; set; }
		public DbSet<Branch> Branches { get; set; }
		public DbSet<Town> Towns { get; set; }
		public DbSet<ApplicationUser> ApplicationUsers { get; set; }
		public DbSet<SystemRole> SystemRoles { get; set; }
		public DbSet<UserRole> UserRoles { get; set; }
		public DbSet<RefreshTokenInfo> RefreshTokenInfos { get; set; }
	}
}
/**public class AppDbContext(DbContextOptions<AppDbContext> options): DbContext(options)
	{*/