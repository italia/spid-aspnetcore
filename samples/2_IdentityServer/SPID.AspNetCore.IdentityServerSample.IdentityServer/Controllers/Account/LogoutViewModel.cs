namespace SPID.AspNetCore.IdentityServerSample.IdentityServer.Controllers
{
    public class LogoutViewModel : LogoutInputModel
    {
        public bool ShowLogoutPrompt { get; set; } = true;
    }
}
