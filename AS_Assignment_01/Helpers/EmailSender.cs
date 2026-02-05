using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AS_Assignment_01.Helpers
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;


        public EmailSender(IConfiguration config, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _httpClientFactory = httpClientFactory;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            await SendOtpEmailAsync(email, htmlMessage);
        }

        public async Task SendOtpEmailAsync(string email, string otp)
        {
            var apiKey = _config["MailerSend:ApiKey"];
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var payload = new
            {
                from = new { email = "no-reply@test-z0vklo6zq1vl7qrx.mlsender.net", name = "Ace Job Agency" },
                to = new[] { new { email } },
                subject = "Your OTP Code",
                template_id = "jy7zpl9d6opg5vx6",
                personalization = new[]
                {
                    new { email, data = new { otpCode = otp, support_email = "support@acejob.com" } }
                }
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync("https://api.mailersend.com/v1/email", content);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                throw new Exception($"Email failed: {response.StatusCode} - {errorBody}");
            }
        }

        public async Task SendResetPasswordEmailAsync(string email, string resetLink, string name)
        {
            var apiKey = _config["MailerSend:ApiKey"];
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var payload = new
            {
                from = new { email = "no-reply@test-z0vklo6zq1vl7qrx.mlsender.net", name = "Ace Job Agency" },
                to = new[] { new { email } },
                subject = "Reset Your Password",
                template_id = " jpzkmgq9jj14059v",
                personalization = new[]
                {
                    new
                    {
                        email,
                        data = new
                        {
                            reset_link = resetLink,
                            name = name,
                            account_name = "Ace Job",
                            support_email = "support@acejob.com"
                        }
                    }
                }
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync("https://api.mailersend.com/v1/email", content);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                throw new Exception($"Email failed: {response.StatusCode} - {errorBody}");
            }
        }
    }
}
