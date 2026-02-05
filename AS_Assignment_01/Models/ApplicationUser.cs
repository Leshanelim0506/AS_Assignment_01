using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AS_Assignment_01.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string FirstName { get; set; } = string.Empty;
        [Required]
        public string LastName { get; set; } = string.Empty;
        [Required]
        public string Gender { get; set; } = string.Empty;
        [Required]
        public string EncryptedNRIC { get; set; } = string.Empty;
        [Required]
        public DateTime DateOfBirth { get; set; }
        [Required]
        public string ResumePath { get; set; } = string.Empty;
        [Required]
        public string WhoAmI { get; set; } = string.Empty;

        public DateTime? LastPasswordChangedDate { get; set; }

        // Advanced Policies
        public string PasswordHistory { get; set; } = string.Empty; // Stores last 2 hashed passwords

        [Required]
        public string PhotoPath { get; set; } = string.Empty;

        public string? CurrentSessionId { get; set; }
    }
}