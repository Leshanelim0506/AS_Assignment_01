using System.ComponentModel.DataAnnotations;

namespace AS_Assignment_01.Models
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public bool RememberMe { get; set; }

        [Required]
        public string RecaptchaToken { get; set; }
    }
}
