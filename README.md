# SPID Remote Authenticator for AspNetCore
This is a custom implementation of an AspNetCore RemoteAuthenticationHandler for SPID (a.k.a. the Italian 'Sistema Pubblico di Identità Digitale').
Since it's an Italian-only thing, there's no point in struggling with an english README, just italian from now on.

Lo scopo di questo progetto è quello di fornire uno strumento semplice ed immediato per integrare, in una WebApp sviluppata con AspNetCore MVC, i servizi di autenticazione di SPID, automatizzando i flussi di login/logout, la gestione del protocollo SAML, la security e semplificando le attività di sviluppo e markup.

# Integrazione

La libreria viene distribuita sotto forma di pacchetto NuGet, installabile tramite il comando
`Install-Package SPID.AspNetCore.Authentication`

Una volta installato, il pacchetto crea nel progetto i link simbolici ad alcuni file di contenuti, necessari per la renderizzazione del pulsante "Entra con SPID"

```
- wwwroot
  - js
    - spid.js
  - css
    - spid.css
  - images
    - spid-ico-circle-bb.png
```

ed aggiunge al progetto il reference a `SPID.AspNetCore.Authentication.dll`.

A questo punto è sufficiente, all'interno dello `Startup.cs`, aggiungere le seguenti righe:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews();
    services
        .AddAuthentication(o => {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = SpidDefaults.AuthenticationScheme;
        })
        .AddSpid(Configuration, o => {
            o.LoadFromConfiguration(Configuration);
        })
        .AddCookie();
}
```

In questo modo vengono aggiunti i middleware necessari per la gestione delle richieste/risposte di login e logout da/verso SPID.

Nella libreraè inclusa anche l'implementazione di un TagHelper per la renderizzazione del pulsante "Entra con SPID" conforme alle direttive.
Per renderizzare il pulsante è sufficiente aggiungere il seguente codice alla View dove lo si desidera posizionare:

```razor
@using SPID.AspNetCore.Authentication
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
@addTagHelper *, SPID.AspNetCore.Authentication
@{
	ViewData["Title"] = "Home Page";
}
@section styles {
	<link rel="stylesheet" href="~/spid/spid.css" />
}

<div class="text-center">
	<h1 class="display-4">Welcome</h1>
	<spid-providers challenge-url="/home/login" size="Medium" class="text-left"></spid-providers>
</div>

@section scripts {
	<script src="~/spid/spid.js"></script>
}
```

Il TagHelper `spid-providers` si occuperà di generare automaticamente il codice HTML necessario per la renderizzazione della lista di IdentityProviders, inizializzata tra le SpidOptions in fase di startup.

# Configurazione
E' possibile configurare la libreria leggendo le impostazioni da Configurazione, tramite il comando

```csharp
o.LoadFromConfiguration(Configuration);
```
In particolare è possibile aggiungere alla configurazione una sezione 'Spid' che ha il seguente formato

```json
  "Spid": {
    "Providers": [
      {
        "Name": "Validator",
        "OrganizationName": "Validator SPID",
        "OrganizationDisplayName": "Validator SPID",
        "OrganizationUrlMetadata": "https://validator.spid.gov.it/metadata.xml",
        "OrganizationUrl": "https://validator.spid.gov.it",
        "OrganizationLogoUrl": "https://validator.spid.gov.it/img/idp-logo.png",
        "SingleSignOnServiceUrl": "https://validator.spid.gov.it/samlsso",
        "SingleSignOutServiceUrl": "https://validator.spid.gov.it/samlsso",
        "Method": "Post",
        "Type": "StagingProvider",
        "PerformFullResponseValidation": true
      },
      {
        "Name": "Local",
        "OrganizationName": "Local",
        "OrganizationDisplayName": "Local",
        "OrganizationUrlMetadata": "http://localhost:8088/metadata",
        "OrganizationUrl": "https://github.com/italia/spid-testenv-docker",
        "OrganizationLogoUrl": "https://validator.spid.gov.it/img/idp-logo.png",
        "SingleSignOnServiceUrl": "http://localhost:8088/sso",
        "SingleSignOutServiceUrl": "http://localhost:8088/slo",
        "Method": "Post",
        "Type": "DevelopmentProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Aruba",
        "OrganizationName": "ArubaPEC S.p.A.",
        "OrganizationDisplayName": "ArubaPEC S.p.A.",
        "OrganizationUrlMetadata": "https://loginspid.aruba.it/metadata",
        "OrganizationUrl": "https://www.pec.it/",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-arubaid.png",
        "SingleSignOnServiceUrl": "https://loginspid.aruba.it/ServiceLoginWelcome",
        "SingleSignOutServiceUrl": "https://loginspid.aruba.it/ServiceLogoutRequest",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Poste",
        "OrganizationName": "Poste Italiane SpA",
        "OrganizationDisplayName": "Poste Italiane SpA",
        "OrganizationUrlMetadata": "https://posteid.poste.it/jod-fs/metadata/metadata.xml",
        "OrganizationUrl": "https://www.poste.it/",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-posteid.png",
        "SingleSignOnServiceUrl": "https://posteid.poste.it/jod-fs/ssoservicepost",
        "SingleSignOutServiceUrl": "https://posteid.poste.it/jod-fs/sloservicepost",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      ........
    ],
    "Certificate": {
      "Source": "Store/File/Raw/None",
      "Store": {
        "Location": "CurrentUser",
        "Name": "My",
        "FindType": "FindBySubjectName",
        "FindValue": "certificatesubjectname",
        "validOnly": false
      },
      "File": {
        "Path": "certificatefilename.pfx",
        "Password": "password" 
      },
      "Raw": {
        "Certificate": "base64rawcertificate-exportedwithprivatekey",
        "Password": "password"
      }
    },
    "IsLocalValidatorEnabled": false,
    "IsStagingValidatorEnabled": true,
    "EntityId": "https://entityID",
    "AssertionConsumerServiceIndex": 0,
    "AttributeConsumingServiceIndex": 0
  }
```

In alternativa, è possibile configurare tutte le suddette opzioni programmaticamente, dal metodo `AddSpid(options => ...)`.

# Punti d'estensione
E' possibile intercettare le varie fasi di esecuzione del RemoteAuthenticator, effettuando l'override degli eventi esposti dalla option Events, ed eventualmente utilizzare la DependencyInjection per avere a disposizione i vari servizi configurati nella webapp.
Questo torna utile sia in fase di inspection delle request e delle response da/verso SPID, sia per personalizzare, a runtime, alcuni parametri per la generazione della richiesta SAML (ad esempio nel caso in cui si voglia implementare la multitenancy). Ad esempio

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews();
    services
        .AddAuthentication(o => {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = SpidDefaults.AuthenticationScheme;
        })
        .AddSpid(Configuration, o => {
            o.Events.OnTokenCreating = async (s) => await s.HttpContext.RequestServices.GetRequiredService<CustomSpidEvents>().TokenCreating(s);
            o.LoadFromConfiguration(Configuration);
        })
        .AddCookie();
    services.AddScoped<CustomSpidEvents>();
}

.....

public class CustomSpidEvents : SpidEvents
{
    private readonly IMyService _myService;
    public CustomSpidEvents(IMyService myService)
    {
        _myService = myService;
    }

    public override Task TokenCreating(SecurityTokenCreatingContext context)
    {
        var customConfig = _myService.ReadMyCustomConfigFromWhereverYouWant();
        context.TokenOptions.EntityId = customConfig.EntityId;
        context.TokenOptions.AssertionConsumerServiceIndex = customConfig.AssertionConsumerServiceIndex;
        context.TokenOptions.AttributeConsumingServiceIndex = customConfig.AttributeConsumingServiceIndex;
        context.TokenOptions.Certificate = customConfig.Certificate;

        return base.TokenCreating(context);
    }
}
```
