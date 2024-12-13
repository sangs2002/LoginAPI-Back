using LoginForm.Model;
using Microsoft.EntityFrameworkCore;

namespace LoginForm.Context
{
    public class UserDBConetext : DbContext
    {
        public UserDBConetext(DbContextOptions<UserDBConetext> options):base(options)
        {

        }

        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
        }
    }
}
