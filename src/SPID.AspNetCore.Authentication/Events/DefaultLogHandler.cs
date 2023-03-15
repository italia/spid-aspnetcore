using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication.Events;

internal class DefaultLogHandler : ILogHandler
{
    public Task LogPostRequest(PostRequest request)
    {
        return Task.CompletedTask;
    }

    public Task LogPostResponse(PostResponse response)
    {
        return Task.CompletedTask;
    }

    public Task LogRedirectRequest(RedirectRequest request)
    {
        return Task.CompletedTask;
    }

    public Task LogRedirectResponse(RedirectResponse response)
    {
        return Task.CompletedTask;
    }
}
