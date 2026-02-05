using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AS_Assignment_01.Data;
using AS_Assignment_01.Models;
using AS_Assignment_01.Helpers;

var builder = WebApplication.CreateBuilder(args);

// --- Services ---
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;

    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// MVC & Email Sender
builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient();
builder.Services.AddScoped<EmailSender>();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug);
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

// Add the filter to the service container
builder.Services.AddScoped<AS_Assignment_01.Filters.SessionCheckFilter>();

builder.Services.AddControllersWithViews(options =>
{
    options.Filters.AddService<AS_Assignment_01.Filters.SessionCheckFilter>();
});

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20); // The 20-minute requirement
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20); // Match your JS for testing
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".AceJob.Session";
});

var app = builder.Build();

// --- Middleware ---
// Static files
app.UseStaticFiles();

// Routing
app.UseRouting();

// Session + Auth
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
// Log every incoming request and any exceptions
app.Use(async (context, next) =>
{
    Console.WriteLine($"[Request] {context.Request.Method} {context.Request.Path}");

    try
    {
        await next(); // call next middleware
        Console.WriteLine($"[Response] {context.Response.StatusCode} for {context.Request.Path}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Exception] {ex.GetType().Name}: {ex.Message}");
        Console.WriteLine(ex.StackTrace);
        throw; // rethrow so DeveloperExceptionPage or ExceptionHandler handles it
    }
});


// --- Error Handling ---
// Must come after UseRouting but before MapControllerRoute
if (app.Environment.IsDevelopment())
{
    // Show detailed errors for development
    app.UseDeveloperExceptionPage();
}
else
{
    // Handles unhandled exceptions (500)
    app.UseExceptionHandler("/Account/Error/500");
}

// Handles 404 / other status codes
app.UseStatusCodePagesWithReExecute("/Account/Error/{0}");

// --- Endpoints / Controllers ---
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}"
);

// Fallback route (optional, catches unmatched URLs)
app.MapControllerRoute(
    name: "fallback",
    pattern: "{*url}",
    defaults: new { controller = "Account", action = "Error", statusCode = 404 }
);

app.Run();
