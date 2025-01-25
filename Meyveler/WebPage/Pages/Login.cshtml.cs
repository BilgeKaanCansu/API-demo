using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

public class LoginModel : PageModel
{
    private readonly HttpClient _httpClient;

    public LoginModel(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("FruitAPI");
    }

    [BindProperty]
    public string Username { get; set; }
    [BindProperty]
    public string Password { get; set; }
    public string ErrorMessage { get; set; }

    public async Task<IActionResult> OnPostAsync()
    {
        var loginData = new
        {
            Username = this.Username,
            Password = this.Password
        };

        var jsonContent = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");

        // API'ye login isteði gönder
        var response = await _httpClient.PostAsync("/login", jsonContent);

        if (response.IsSuccessStatusCode)
        {
            // Baþarýlý giriþ, gelen token'ý al
            var result = await response.Content.ReadAsStringAsync();

            // Token'ý session'a kaydet
            HttpContext.Session.SetString("JwtToken", result);

            // Ana sayfaya yönlendir
            return RedirectToPage("/Index");
        }
        else
        {
            // Hata mesajýný göster
            ErrorMessage =response.ReasonPhrase;
            return Page();
        }
    }
}
