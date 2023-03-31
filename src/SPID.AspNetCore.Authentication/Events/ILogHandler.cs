using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication.Events;

public interface ILogHandler
{
    public Task LogPostRequest(PostRequest request);

    public Task LogPostResponse(PostResponse response);

    public Task LogRedirectRequest(RedirectRequest request);

    public Task LogRedirectResponse(RedirectResponse response);


}
