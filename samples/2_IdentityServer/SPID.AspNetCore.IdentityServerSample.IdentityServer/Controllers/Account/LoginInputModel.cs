using System.ComponentModel.DataAnnotations;

namespace SPID.AspNetCore.IdentityServerSample.IdentityServer.Controllers
{
    public class LoginInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }
}