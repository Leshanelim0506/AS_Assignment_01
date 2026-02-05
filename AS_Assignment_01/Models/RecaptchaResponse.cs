using System.ComponentModel.DataAnnotations;

namespace AS_Assignment_01.Models
{
    public class RecaptchaResponse
    {
        public bool success { get; set; }
        public double score { get; set; }
        public string? action { get; set; }
        public string? hostname { get; set; }
        public List<string>? error_codes { get; set; }
    }
}
