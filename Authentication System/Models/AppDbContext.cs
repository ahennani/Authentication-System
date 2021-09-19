using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication_System.Models
{
    public class AppDbContext : DbContext
    {
        public DbSet<AppUser> AppUsers { get; set; }
        public DbSet<Provider> Providers { get; set; }

        public AppDbContext(DbContextOptions dbContextOptions):base(dbContextOptions) {}

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<AppUser>(entity =>
            {
                entity.ToTable("Users");
                entity.HasKey(k => k.UserId);
                entity.HasIndex(k => k.Username).IsUnique();
                entity.HasIndex(k => k.Email).IsUnique();
                entity.Property(p => p.Firstname).HasMaxLength(50);
                entity.Property(p => p.Lastname).HasMaxLength(50);
                entity.Property(p => p.Email).HasMaxLength(55);
                entity.Property(p => p.Email).HasMaxLength(55);
            });

            modelBuilder.Entity<Provider>(entityProvider =>
            {
                entityProvider.ToTable("Provider");
                entityProvider.HasKey(k => k.ProviderId);
                entityProvider.HasOne<AppUser>(p => p.User)
                              .WithMany(u => u.Providers)
                              .OnDelete(DeleteBehavior.Restrict);
                entityProvider.HasIndex(p => p.Name).IsUnique();
                entityProvider.Property(p => p.Name).HasMaxLength(20);
            });
        }

    }
}
