using AS_Assignment_01.Models;
using AS_Assignment_01.Helpers;
using AS_Assignment_01.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Authorization;
using System.Net;
using System.Text.Json;

namespace AS_Assignment_01.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly EmailSender _emailSender;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext context,
            EmailSender emailSender,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _emailSender = emailSender;
            _configuration = configuration;
        }

        // ================= ANTI-BOT HELPER =================
        private async Task<bool> VerifyRecaptcha(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            var secret = _configuration["Recaptcha:SecretKey"] ?? "6Ld6sl0sAAAAAG5n0rUWBkQNUXJeLPe7cZo6ZvJZ";
            using var client = new HttpClient();

            try
            {
                var response = await client.PostAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secret}&response={token}",
                    null
                );

                if (!response.IsSuccessStatusCode) return false;

                var json = await response.Content.ReadAsStringAsync();
                var data = JsonSerializer.Deserialize<RecaptchaResponse>(json);

                // For v2, just check 'success' (v3 has score)
                return data != null && data.success;
            }
            catch
            {
                return false;
            }
        }

        private class RecaptchaResponse
        {
            public bool success { get; set; }
            public double score { get; set; }
            public string action { get; set; }
            public string hostname { get; set; }
            public List<string>? error_codes { get; set; }
        }

        // ================= REGISTER =================

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult> SendRegistrationOTP([FromBody] OtpRequest request)
        {
            if (string.IsNullOrEmpty(request?.Email))
                return Json(new { success = false, message = "Email is required" });

            string otp = new Random().Next(100000, 999999).ToString();
            HttpContext.Session.SetString("RegistrationOTP", otp);
            HttpContext.Session.SetString("OTPEmail", request.Email);

            try
            {
                await _emailSender.SendEmailAsync(request.Email, "Registration OTP", otp);
                return Json(new { success = true });
            }
            catch
            {
                return Json(new { success = false, message = "Failed to send OTP." });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string userOTP, IFormFile photoFile, IFormFile resumeFile)
        {
            // 1. Session & OTP Verification
            string? sessionOTP = HttpContext.Session.GetString("RegistrationOTP");
            string? sessionEmail = HttpContext.Session.GetString("OTPEmail");

            if (sessionOTP != userOTP || sessionEmail != model.Email)
            {
                ModelState.AddModelError("", "Invalid or expired OTP. Please verify your email again.");
                return View(model);
            }

            // 2. Explicit Duplicate Email Check
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "This email address is already registered.");
                return View(model);
            }

            if (!ModelState.IsValid) return View(model);

            // 3. Secure File Upload Handling
            string photoPath = "default.jpg";
            if (photoFile != null && photoFile.Length > 0)
            {
                // Verification: Check both Extension and MIME Type 
                var photoExt = Path.GetExtension(photoFile.FileName).ToLower();

                // Only allow .JPG extension and image/jpeg MIME type 
                if ((photoExt != ".jpg" && photoExt != ".jpeg") || photoFile.ContentType.ToLower() != "image/jpeg")
                {
                    ModelState.AddModelError("", "Security Violation: Only authentic .JPG images are permitted.");
                    return View(model);
                }

                // Rename the file using a GUID before saving to prevent Path Injection 
                photoPath = await SaveFile(photoFile, "uploads");
            }
            string resumePath = string.Empty;
            if (resumeFile != null && resumeFile.Length > 0)
            {
                var resumeExt = Path.GetExtension(resumeFile.FileName).ToLower();

                // Define valid MIME types for PDF and DOCX
                var allowedMimeTypes = new[] { "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };

                if ((resumeExt != ".pdf" && resumeExt != ".docx") || !allowedMimeTypes.Contains(resumeFile.ContentType))
                {
                    ModelState.AddModelError("", "Invalid format. Only authentic .PDF or .DOCX files are allowed.");
                    return View(model);
                }

                resumePath = await SaveFile(resumeFile, "uploads/resumes");
            }

            // 4. Create User with Configuration-based Encryption
            // Inside the Register POST method
            var encryptionKey = _configuration["EncryptionSettings:Key"]; // Matches your appsettings.json
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = WebUtility.HtmlEncode(model.FirstName),
                LastName = WebUtility.HtmlEncode(model.LastName),
                // Pass two arguments: the data and the key
                EncryptedNRIC = EncryptionHelper.Encrypt(model.NRIC, encryptionKey),
                Gender = model.Gender,
                DateOfBirth = model.DateOfBirth,
                WhoAmI = model.WhoAmI,
                PhotoPath = photoPath,
                ResumePath = resumePath,
                LastPasswordChangedDate = DateTime.Now
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await CreateAuditLog(model.Email, "Registration Successful");
                return RedirectToAction("Login");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View(model);
        }

        // Helper method to save files securely
        private async Task<string> SaveFile(IFormFile file, string subFolder)
        {
            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", subFolder);
            if (!Directory.Exists(uploadsFolder)) Directory.CreateDirectory(uploadsFolder);

            var uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(file.FileName);
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(fileStream);
            }
            return uniqueFileName;
        }

        // ================= LOGIN =================

        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (!await VerifyRecaptcha(model.RecaptchaToken))
            {
                await CreateAuditLog(model.Email, "Login Failed: Bot detected");
        ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                return View(model);
            }
            
            var result = await _signInManager.PasswordSignInAsync(
                model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    // Create a unique identifier for this specific login instance
                    string uniqueLoginGuid = Guid.NewGuid().ToString();
                    HttpContext.Session.SetString("AuthSessionId", uniqueLoginGuid);

                    // Store it in the Database to "invalidate" previous session IDs
                    user.CurrentSessionId = uniqueLoginGuid;
                    await _userManager.UpdateAsync(user);
                }
                await CreateAuditLog(model.Email, "Login Successful");
                return RedirectToAction("Index");
            }

            if (result.IsLockedOut)
            {
                await CreateAuditLog(model.Email, "Account Locked Out");
        ModelState.AddModelError("", "Account locked due to 3 failed attempts. Try again in 15 mins.");
        return View(model);
            }

            ModelState.AddModelError("", "Invalid login.");
            return View(model);
        }

        // ================= PROFILE (INDEX) =================

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            // 1. Retrieve the authenticated user
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToAction("Login");

            // 2. PASSWORD AGE POLICY (Advanced Requirement) 
                        // Check if the password has exceeded the maximum allowed age
            var maxPasswordAgeMinutes = 60; // Requirement: "must change password after x mins" 

            if (user.LastPasswordChangedDate.HasValue)
            {
                var timeElapsed = DateTime.Now - user.LastPasswordChangedDate.Value;
                if (timeElapsed.TotalMinutes > maxPasswordAgeMinutes)
                {
                    // Requirement: Force the user to change password after expiration 
                                // We pass a flag to the view to explain why they were redirected
                    TempData["PasswordExpired"] = "Your password has expired. Please update it to continue.";
                    return RedirectToAction("ChangePassword");
                }
            }

            // 3. DATA PROTECTION (Homepage Requirement) 
            // Requirement: Decryption of customer data to display in homepage 
            var encryptionKey = _configuration["SecuritySettings:EncryptionKey"];

            try
            {
                // Decrypt the NRIC using the key from configuration 
                ViewBag.DecryptedNRIC = EncryptionHelper.Decrypt(user.EncryptedNRIC, encryptionKey);
            }
            catch
            {
                // Fail-safe in case of encryption mismatch
                ViewBag.DecryptedNRIC = "Error decrypting data";
            }

            return View(user);
        }

        // ================= LOGOUT =================

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                
                await CreateAuditLog(user.Email!, "Logout Successful");

                // 2. Clear the Session ID in the database to prevent dangling sessions
                user.CurrentSessionId = null;
                await _userManager.UpdateAsync(user);
            }

            
            await _signInManager.SignOutAsync();

            // 4. Wipe the local session data
            HttpContext.Session.Clear();

            return RedirectToAction("Login");
        }

        // ================= AUDIT LOGGING =================

        private async Task CreateAuditLog(string email, string activity)
        {
            _context.AuditLogs.Add(new AuditLog
            {
                UserEmail = email,
                Activity = activity,
                Timestamp = DateTime.Now,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            });
            await _context.SaveChangesAsync();
        }

        // ================= PASSWORD MANAGEMENT =================

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return RedirectToAction("ForgotPasswordConfirmation");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action(
                "ResetPassword", "Account",
                new { email = model.Email, token = token },
                Request.Scheme
            );

            await _emailSender.SendResetPasswordEmailAsync(user.Email!, resetLink!, user.FirstName);
            return RedirectToAction("ForgotPasswordConfirmation");
        }

        [HttpGet]
        public IActionResult ForgotPasswordConfirmation() => View();

        [HttpGet]
        public IActionResult ForgotPassword() => View();

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            if (token == null || email == null) return BadRequest();
            var model = new ResetPasswordViewModel { Token = token, Email = email };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return RedirectToAction("ResetPasswordConfirmation");

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                user.LastPasswordChangedDate = DateTime.Now;
                await _userManager.UpdateAsync(user);
                return RedirectToAction("ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation() => View();

        [Authorize]
        [HttpGet]
        public IActionResult ChangePassword() => View();

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToAction("Login");

            // NEW: Check History (Requirement: Avoid reuse of max 2)
            var newHash = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
            string[] history = user.PasswordHistory.Split(';', StringSplitOptions.RemoveEmptyEntries);

            foreach (var oldHash in history)
            {
                var verificationResult = _userManager.PasswordHasher.VerifyHashedPassword(user, oldHash, model.NewPassword);
                if (verificationResult == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "You cannot reuse your last 2 passwords.");
                    return View(model);
                }
            }

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                // Update History: Keep only last 2
                var currentHash = user.PasswordHash;
                var newHistoryList = history.ToList();
                newHistoryList.Add(currentHash);
                if (newHistoryList.Count > 2) newHistoryList.RemoveAt(0);
                user.PasswordHistory = string.Join(";", newHistoryList);

                user.LastPasswordChangedDate = DateTime.Now;
                await _userManager.UpdateAsync(user);
                await _signInManager.RefreshSignInAsync(user);
                await CreateAuditLog(user.Email!, "Password Changed Successfully");
                return RedirectToAction("Index");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View(model);
        }

        [Route("Account/Error/{statusCode?}")]
        public IActionResult Error(int? statusCode = null)
        {
            int code = statusCode ?? 500;
            Response.StatusCode = code;
            return View("~/Views/Shared/Error.cshtml", code);
        }
    }

    public class OtpRequest
    {
        public string? Email { get; set; }
    }
}