using Microsoft.AspNetCore.Mvc.RazorPages;
using FruitWebApp.Models;
using System.Text.Json;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Net.Http.Headers;

namespace FruitWebApp.Pages
{
    public class IndexModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public IndexModel(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
        {
            _httpClientFactory = httpClientFactory;
            _httpContextAccessor = httpContextAccessor;
        }

        [BindProperty]
        public IEnumerable<FruitModel> FruitModels { get; set; }

        public async Task<IActionResult> OnGet()
        {
            var token = _httpContextAccessor.HttpContext.Session.GetString("JwtToken");
            if (string.IsNullOrEmpty(token))
            {
                return RedirectToPage("/Login");
            }

            var httpClient = _httpClientFactory.CreateClient("FruitAPI");
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, "/fruitlist");
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using (var response = await httpClient.SendAsync(requestMessage))
            {
                if (response.IsSuccessStatusCode)
                {
                    using var contentStream = await response.Content.ReadAsStreamAsync();
                    FruitModels = await JsonSerializer.DeserializeAsync<IEnumerable<FruitModel>>(contentStream);
                }
                else
                {
                    ViewData["ErrorMessage"] = "Error retrieving data from the API.";
                }
            }

            return Page();
        }
    }
}
