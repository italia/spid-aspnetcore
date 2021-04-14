# AspNetCore Remote Authenticator for SPID
This is a custom implementation of an AspNetCore RemoteAuthenticationHandler for SPID (a.k.a. the Italian 'Sistema Pubblico di Identità Digitale').
Since it's an Italian-only thing, there's no point in struggling with an english README, just italian from now on.

Lo scopo di questo progetto è quello di fornire uno strumento semplice ed immediato per integrare, in una WebApp sviluppata con AspNetCore MVC, i servizi di autenticazione di SPID, automatizzando i flussi di login/logout, la gestione del protocollo SAML, la security e semplificando le attività di sviluppo e markup.

# Integrazione

La libreria viene distribuita sotto forma di pacchetto NuGet, installabile tramite il comando

`Install-Package SPID.AspNetCore.Authentication`

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

In questo modo vengono aggiunti i middleware necessari per la gestione delle richieste/risposte di login/logout da/verso SPID.

Nella libreria è inclusa anche l'implementazione di un TagHelper per la renderizzazione (conforme alle specifiche) del pulsante "Entra con SPID".
Per renderizzare il pulsante è sufficiente aggiungere il seguente codice alla View Razor dove lo si desidera posizionare:

```razor
@using SPID.AspNetCore.Authentication
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
@addTagHelper *, SPID.AspNetCore.Authentication
@{
	ViewData["Title"] = "Home Page";
}
@section styles {
	<style spid></style>
}
<div class="text-center">
	<h1 class="display-4">Welcome</h1>
	<spid-providers challenge-url="/home/login" size="Medium" class="text-left"></spid-providers>
</div>

@section scripts {
	<script spid></script>
}
```

Il TagHelper `spid-providers` si occuperà di generare automaticamente il codice HTML necessario per la renderizzazione della lista di IdentityProviders che è stata inizializzata tra le SpidOptions in fase di startup. `<style spid></style>` e `<script spid></script>` invece rappresentano i TagHelper per la renderizzazione rispettivamente delle classi CSS e del codice JS necessari all'esecuzione del pulsante.
Un esempio completo di webapp AspNetCore MVC che fa uso di questa libreria è presente all'interno di questo repository sotto la cartella `SPID.AspNetCore.Authentication/SPID.AspNetCore.WebApp`. Per utilizzarla è sufficiente configurare in `appsettings.json` i parametri `AssertionConsumerServiceIndex`, `AttributeConsumingServiceIndex`, `EntityId` e `Certificate` con quelli relativi al proprio metadata di test, e lanciare la webapp.

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
      {
        "Name": "Intesa",
        "OrganizationName": "IN.TE.S.A. S.p.A.",
        "OrganizationDisplayName": "IN.TE.S.A. S.p.A.",
        "OrganizationUrlMetadata": "https://spid.intesa.it/metadata/metadata.xml",
        "OrganizationUrl": "https://www.intesa.it/",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-intesaid.png",
        "SingleSignOnServiceUrl": "https://spid.intesa.it/Time4UserServices/services/idp/AuthnRequest/",
        "SingleSignOutServiceUrl": "https://spid.intesa.it/Time4UserServices/services/idp/SingleLogout",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Infocert",
        "OrganizationName": "InfoCert S.p.A.",
        "OrganizationDisplayName": "InfoCert S.p.A.",
        "OrganizationUrlMetadata": "https://identity.infocert.it/metadata/metadata.xml",
        "OrganizationUrl": "https://www.infocert.it",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-infocertid.png",
        "SingleSignOnServiceUrl": "https://identity.infocert.it/spid/samlsso",
        "SingleSignOutServiceUrl": "https://identity.infocert.it/spid/samlslo",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Lepida",
        "OrganizationName": "Lepida S.p.A.",
        "OrganizationDisplayName": "Lepida S.p.A.",
        "OrganizationUrlMetadata": "https://id.lepida.it/idp/shibboleth",
        "OrganizationUrl": "https://www.lepida.it",
        "OrganizationLogoUrl": "https://id.lepida.it/idm/app/pubblica/lepida_spid.png",
        "SingleSignOnServiceUrl": "https://id.lepida.it/idp/profile/SAML2/POST/SSO",
        "SingleSignOutServiceUrl": "https://id.lepida.it/idp/profile/SAML2/POST/SLO",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Namirial",
        "OrganizationName": "Namirial S.p.a.",
        "OrganizationDisplayName": "Namirial S.p.a.",
        "OrganizationUrlMetadata": "https://idp.namirialtsp.com/idp/metadata",
        "OrganizationUrl": "https://www.namirialtsp.com",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-namirialid.png",
        "SingleSignOnServiceUrl": "https://idp.namirialtsp.com/idp/profile/SAML2/POST/SSO",
        "SingleSignOutServiceUrl": "https://idp.namirialtsp.com/idp/profile/SAML2/POST/SLO",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Register",
        "OrganizationName": "Register.it S.p.A.",
        "OrganizationDisplayName": "Register.it S.p.A.",
        "OrganizationUrlMetadata": "https://spid.register.it/login/metadata",
        "OrganizationUrl": "https//www.register.it",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-spiditalia.png",
        "SingleSignOnServiceUrl": "https://spid.register.it/login/sso",
        "SingleSignOutServiceUrl": "https://spid.register.it/login/singleLogout",
        "Method": "Post",
        "Type": "IdentityProvider",
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Sielte",
        "OrganizationName": "Sielte S.p.A.",
        "OrganizationDisplayName": "Sielte S.p.A.",
        "OrganizationUrlMetadata": "https://identity.sieltecloud.it/simplesaml/metadata.xml",
        "OrganizationUrl": "http://www.sielte.it",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-sielteid.png",
        "SingleSignOnServiceUrl": "https://identity.sieltecloud.it/simplesaml/saml2/idp/SSO.php",
        "SingleSignOutServiceUrl": "https://identity.sieltecloud.it/simplesaml/saml2/idp/SLO.php",
        "Method": "Post",
        "Type": "IdentityProvider",
        "NowDelta": -2,
        "PerformFullResponseValidation": false
      },
      {
        "Name": "Tim",
        "OrganizationName": "Trust Technologies srl",
        "OrganizationDisplayName": "Trust Technologies srl",
        "OrganizationUrlMetadata": "https://login.id.tim.it/spid-services/MetadataBrowser/idp",
        "OrganizationUrl": "https://www.trusttechnologies.it",
        "OrganizationLogoUrl": "https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos/spid-idp-timid.png",
        "SingleSignOnServiceUrl": "https://login.id.tim.it/affwebservices/public/saml2sso",
        "SingleSignOutServiceUrl": "https://login.id.tim.it/affwebservices/public/saml2slo",
        "Method": "Post",
        "Type": "IdentityProvider",
        "NowDelta": -2,
        "PerformFullResponseValidation": false
      }
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
    "AttributeConsumingServiceIndex": 0,
    "RandomIdentityProvidersOrder": false
  }
```
La configurazione del certificato del SP avviene specificando nel campo `Source` uno tra i valori `Store/File/Raw/None` (nel caso di `None` non verrà caricato un certificato durante lo startup, ma sarà necessario fornirne uno a runtime, tramite l'uso dei `CustomSpidEvents`, che verranno presentati più nel dettaglio nella sezione successiva) e compilando opportunamente la sezione corrispondente al valore specificato. Le sezioni non usate (quelle cioè corrispondenti agli altri valori) potranno essere tranquillamente eliminate dal file di configurazione, dal momento che non verranno lette.

In alternativa, è possibile configurare tutte le suddette opzioni programmaticamente, dal metodo `AddSpid(options => ...)`.
Gli endpoint di callback per le attività di signin e signout sono impostati di default, rispettivamente, a `/signin-spid` e `/signout-spid`, ma laddove fosse necessario modificare queste impostazioni, è possibile sovrascriverle (sia da configurazione che da codice) reimpostando le options `CallbackPath` e `RemoteSignOutPath`.

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
            o.Events.OnAuthenticationSuccess = async (s) => await s.HttpContext.RequestServices.GetRequiredService<CustomSpidEvents>().AuthenticationSuccess(s);
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
    
    public override Task AuthenticationSuccess(AuthenticationSuccessContext context)
    {
        var principal = context.Principal;
	
	// Recupero dati provenienti da Spid da ClaimsPrincipal
        var spidCode = principal.FindFirst(SpidClaimTypes.SpidCode);
        var name = principal.FindFirst(SpidClaimTypes.Name);
        var surname = principal.FindFirst(SpidClaimTypes.Surname);
        var email = principal.FindFirst(SpidClaimTypes.Email);
        var fiscalCode = principal.FindFirst(SpidClaimTypes.FiscalNumber);
        // ............etc........
	
        return base.AuthenticationSuccess(context);
    }

}
```

# Error Handling
La libreria può, in qualunque fase (sia in fase di creazione della Request sia in fase di gestione della Response), sollevare eccezioni. 
Un tipico scenario è quello in cui vengono ricevuti i codici di errore previsti dal protocollo SPID (n.19, n.20, ecc....), in tal caso la libreria solleva un'eccezione contenente il corrispondente messaggio d'errore localizzato, richiesto dalle specifiche SPID, che è possibile gestire (ad esempio per la visualizzazione) utilizzando il normale flusso previsto per AspNetCore. L'esempio seguente fa uso del middleware di ExceptionHandling di AspNetCore.

```csharp
public void Configure(IApplicationBuilder app, IHostEnvironment env)
{
    ...
    app.UseExceptionHandler("/Home/Error");
    ...
}

.......

// HomeController
[AllowAnonymous]
public async Task<IActionResult> Error()
{
    var exceptionHandlerPathFeature =
        HttpContext.Features.Get<IExceptionHandlerPathFeature>();

    string errorMessage = string.Empty;

    if (exceptionHandlerPathFeature?.Error != null)
    {
        var messages = FromHierarchy(exceptionHandlerPathFeature?.Error, ex => ex.InnerException)
            .Select(ex => ex.Message)
            .ToList();
        errorMessage = String.Join(" ", messages);
    }

    return View(new ErrorViewModel
    {
        RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
        Message = errorMessage
    });
}

private IEnumerable<TSource> FromHierarchy<TSource>(TSource source,
            Func<TSource, TSource> nextItem,
            Func<TSource, bool> canContinue)
{
    for (var current = source; canContinue(current); current = nextItem(current))
    {
        yield return current;
    }
}

private IEnumerable<TSource> FromHierarchy<TSource>(TSource source,
    Func<TSource, TSource> nextItem)
    where TSource : class
{
    return FromHierarchy(source, nextItem, s => s != null);
}
```

# Compatibilità con Bootstrap
Se la WebApp utilizza Bootstrap, è necessario aggiungere la seguente classe al fine di visualizzare correttamente il pulsante "Entra con SPID"

```css
.spid-idp-button * {
  box-sizing: content-box;
}
```

# Compliance
La libreria è stata oggetto di collaudo da parte di AGID, sia per soluzioni come ServiceProvider che come Aggregatore, ha superato tutti i test di [spid-saml-check](https://github.com/italia/spid-saml-check) ed è compliant con le direttive specificate negli avvisi SPID.

# Authors
* [Daniele Giallonardo](https://github.com/danielegiallonardo) (maintainer) - [Stefano Mostarda](https://github.com/sm15455)
