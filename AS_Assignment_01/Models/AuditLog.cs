using System.ComponentModel.DataAnnotations;

namespace AS_Assignment_01.Models // Add this namespace
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserEmail { get; set; } = string.Empty;

        [Required]
        public string Activity { get; set; } = string.Empty;

        [Required]
        public DateTime Timestamp { get; set; }

        public string IPAddress { get; set; } = string.Empty;
    }
}