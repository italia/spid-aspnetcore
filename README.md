# AspNetCore Remote Authenticator for SPID
This is a custom implementation of an AspNetCore RemoteAuthenticationHandler for SPID (a.k.a. the Italian 'Sistema Pubblico di Identità Digitale').
Since it's an Italian-only thing, there's no point in struggling with an english README, just italian from now on.

Lo scopo di questo progetto è quello di fornire uno strumento semplice ed immediato per integrare, in una WebApp sviluppata con AspNetCore MVC, i servizi di autenticazione di SPID, automatizzando i flussi di login/logout, la gestione del protocollo SAML, la security e semplificando le attività di sviluppo e markup.
All'interno del repository è presente sia il codice della libreria (SPID.AspNetCore.Authentication), che una web app demo (SPID.AspNetCore.WebApp) che mostra una integrazione di esempio della libreria all'interno di un'app AspNetCore ed è utilizzata anche nell'action di CI per la validazione dei test di compliance.

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

In questo modo vengono aggiunti i middleware necessari per la gestione delle richieste/risposte di login/logout da/verso SPID. Tali middleware aggiungono alla webapp gli endpoint `/signin-spid` e `/signout-spid` sui quali la libreria è in ascolto per interpretare le risposte rispettivamente di Login e Logout provenienti dagli IdentityProvider di spid. Tali endpoint, nella loro URL assoluta, e quindi comprensivi di schema e hostname (ad esempio `https://webapp.customdomain.it/signin-spid` e `https://webapp.customdomain.it/signout-spid`), devono essere indicati rispettivamente nei tag `AssertionConsumerService` e `SingleLogoutService` del metadata del SP.

Nella libreria è inclusa anche l'implementazione di un TagHelper per la renderizzazione (conforme alle specifiche) del pulsante "Entra con SPID".
Per renderizzare il pulsante è sufficiente aggiungere il seguente codice alla View Razor dove lo si desidera posizionare:

```razor
@using SPID.AspNetCore.Authentication
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
@addTagHelper *, SPID.AspNetCore.Authentication
@{
	ViewData["Title"] = "Login Page";
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

Il TagHelper `spid-providers` si occuperà di generare automaticamente il codice HTML necessario per la renderizzazione della lista di IdentityProviders che è stata recuperata in automatico dallo SPID Registry in fase di startup. L'attributo `size` può essere valorizzato con i valori `Small, Medium, Large, ExtraLarge`.
`<style spid></style>` e `<script spid></script>` invece rappresentano i TagHelper per la renderizzazione rispettivamente delle classi CSS e del codice JS necessari all'esecuzione del pulsante.
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
        "EntityId": "https://validator.spid.gov.it",
        "Name": "Validator",
        "OrganizationName": "Validator SPID",
        "OrganizationDisplayName": "Validator SPID",
        "X509SigningCertificate": "MIIEfzCCA2egAwIBAgIUVSeD58C3IyG/SwADsok3KChutAAwDQYJKoZIhvcNAQELBQAwgc4xCzAJBgNVBAYTAklUMQ0wCwYDVQQIDARSb21lMQ0wCwYDVQQHDARSb21lMS0wKwYDVQQKDCRBZ0lEIC0gQWdlbnppYSBwZXIgbCdJdGFsaWEgRGlnaXRhbGUxLDAqBgNVBAsMI0FnSUQgLSBTZXJ2aXppbyBhY2NyZWRpdGFtZW50byBTUElEMR4wHAYDVQQDDBV2YWxpZGF0b3Iuc3BpZC5nb3YuaXQxJDAiBgkqhkiG9w0BCQEWFXNwaWQudGVjaEBhZ2lkLmdvdi5pdDAeFw0yMTA5MjgwNzM5MTFaFw0yMzA5MjgwNzM5MTFaMIHOMQswCQYDVQQGEwJJVDENMAsGA1UECAwEUm9tZTENMAsGA1UEBwwEUm9tZTEtMCsGA1UECgwkQWdJRCAtIEFnZW56aWEgcGVyIGwnSXRhbGlhIERpZ2l0YWxlMSwwKgYDVQQLDCNBZ0lEIC0gU2Vydml6aW8gYWNjcmVkaXRhbWVudG8gU1BJRDEeMBwGA1UEAwwVdmFsaWRhdG9yLnNwaWQuZ292Lml0MSQwIgYJKoZIhvcNAQkBFhVzcGlkLnRlY2hAYWdpZC5nb3YuaXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjbuxHXdLPZZc/b9YaSqxdUsdDLYNdpBjdEmPoNf2LrXlBv8IODStRkNyQsAnOdy+R7Ud+kdtJi+tblx8e29RHRSsvl6HL3O0/3aS9XsyUGhbUE45SLxNWTMubU7UyS1mRhSdEUIbtVxYgSu1uH6zeIN2DhxQZIb0APZ7aLbJewu25qECz2dnV54R45pBwst/6MrnBa15VfKDRA2zdgfGjIgGWgxWtf7CqzfXnhush0IyaL4RVn/7tUurxj//LY6f37yMP1EAIbn9thc37ZhyfM9grAH3Cc4kdEB+HaiQ83fTH6LshPgTHww0w88TxK1jrV/vEG3T6ZhCqXt7qRvKtAgMBAAGjUzBRMB0GA1UdDgQWBBT0HytnpUbkZxLa0N+lfD08WrQX2TAfBgNVHSMEGDAWgBT0HytnpUbkZxLa0N+lfD08WrQX2TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCYcghyQ6zhRmLDzliNgJxPUOTJa/9UmZRgWYFcYHMumXTTTT/fmy00hTRFIKWpB0AibyEJhODIjCqNJN3RsCDbkwEDR0thhMQ51vK8oB9X1JVMDQ8v+eRTQTa8bZv8W8IPn7fgQFoX5IkiXEQtgf+hi/ErX/L4O6qbYxE/lIZneXXxlZUVM4YN9aS25nmuCumg9MbrmCCwplliKgKSZ77IERmcFm1tzpEFMJNI8LIaDL8VLSOosIMdLwel3oP3mosTw2hkSfyVUwHp/0y4rJ+zIel/4vBoySsyrJCCi8wBe9WNpIlUV/gGSayPkJMe0qc8m0GzncZDkqF/Bd7xsUHc",
        "OrganizationLogoUrl": "https://validator.spid.gov.it/img/idp-logo.png",
        "SingleSignOnServiceUrlPost": "https://validator.spid.gov.it/samlsso",
        "SingleSignOutServiceUrlPost": "https://validator.spid.gov.it/samlsso",
        "SingleSignOnServiceUrlRedirect": "https://validator.spid.gov.it/samlsso",
        "SingleSignOutServiceUrlRedirect": "https://validator.spid.gov.it/samlsso",
        "Type": "StagingProvider"
      },
      {
        "EntityId": "https://localhost:8080",
        "Name": "SpidSpTest",
        "OrganizationName": "SpidSpTest",
        "OrganizationDisplayName": "SpidSpTest",
        "X509SigningCertificate": "MIIEGDCCAwCgAwIBAgIJAOrYj9oLEJCwMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDAeFw0xOTA0MTExMDAyMDhaFw0yNTAzMDgxMDAyMDhaMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kJVo+ugRrbbv9xhXCuVrqi4B7/MQzQc62ocwlFFujJNd4m1mXkUHFbgvwhRkQqo2DAmFeHiwCkJT3K1eeXIFhNFFroEzGPzONyekLpjNvmYIs1CFvirGOj0bkEiGaKEs+/umzGjxIhy5JQlqXE96y1+Izp2QhJimDK0/KNij8I1bzxseP0Ygc4SFveKS+7QO+PrLzWklEWGMs4DM5Zc3VRK7g4LWPWZhKdImC1rnS+/lEmHSvHisdVp/DJtbSrZwSYTRvTTz5IZDSq4kAzrDfpj16h7b3t3nFGc8UoY2Ro4tRZ3ahJ2r3b79yK6C5phY7CAANuW3gDdhVjiBNYs0CAwEAAaOByjCBxzAdBgNVHQ4EFgQU3/7kV2tbdFtphbSA4LH7+w8SkcwwgZcGA1UdIwSBjzCBjIAU3/7kV2tbdFtphbSA4LH7+w8SkcyhaaRnMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdIIJAOrYj9oLEJCwMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJNFqXg/V3aimJKUmUaqmQEEoSc3qvXFITvT5f5bKw9yk/NVhR6wndL+z/24h1OdRqs76blgH8k116qWNkkDtt0AlSjQOx5qvFYh1UviOjNdRI4WkYONSw+vuavcx+fB6O5JDHNmMhMySKTnmRqTkyhjrch7zaFIWUSV7hsBuxpqmrWDoLWdXbV3eFH3mINA5AoIY/m0bZtzZ7YNgiFWzxQgekpxd0vcTseMnCcXnsAlctdir0FoCZztxMuZjlBjwLTtM6Ry3/48LMM8Z+lw7NMciKLLTGQyU8XmKKSSOh0dGh5Lrlt5GxIIJkH81C0YimWebz8464QPL3RbLnTKg+c=",
        "OrganizationLogoUrl": "https://validator.spid.gov.it/img/idp-logo.png",
        "SingleSignOnServiceUrlPost": "https://localhost:8080/samlsso",
        "SingleSignOutServiceUrlPost": "https://localhost:8080/samlsso",
        "SingleSignOnServiceUrlRedirect": "https://localhost:8080/samlsso",
        "SingleSignOutServiceUrlRedirect": "https://localhost:8080/samlsso",
        "Type": "DevelopmentProvider"
      },
      {
        "EntityId": "https://demo.spid.gov.it/validator",
        "Name": "DemoSpid",
        "OrganizationName": "DemoSpid",
        "OrganizationDisplayName": "DemoSpid",
        "X509SigningCertificate": "MIIEGDCCAwCgAwIBAgIJAOrYj9oLEJCwMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDAeFw0xOTA0MTExMDAyMDhaFw0yNTAzMDgxMDAyMDhaMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kJVo+ugRrbbv9xhXCuVrqi4B7/MQzQc62ocwlFFujJNd4m1mXkUHFbgvwhRkQqo2DAmFeHiwCkJT3K1eeXIFhNFFroEzGPzONyekLpjNvmYIs1CFvirGOj0bkEiGaKEs+/umzGjxIhy5JQlqXE96y1+Izp2QhJimDK0/KNij8I1bzxseP0Ygc4SFveKS+7QO+PrLzWklEWGMs4DM5Zc3VRK7g4LWPWZhKdImC1rnS+/lEmHSvHisdVp/DJtbSrZwSYTRvTTz5IZDSq4kAzrDfpj16h7b3t3nFGc8UoY2Ro4tRZ3ahJ2r3b79yK6C5phY7CAANuW3gDdhVjiBNYs0CAwEAAaOByjCBxzAdBgNVHQ4EFgQU3/7kV2tbdFtphbSA4LH7+w8SkcwwgZcGA1UdIwSBjzCBjIAU3/7kV2tbdFtphbSA4LH7+w8SkcyhaaRnMGUxCzAJBgNVBAYTAklUMQ4wDAYDVQQIEwVJdGFseTENMAsGA1UEBxMEUm9tZTENMAsGA1UEChMEQWdJRDESMBAGA1UECxMJQWdJRCBURVNUMRQwEgYDVQQDEwthZ2lkLmdvdi5pdIIJAOrYj9oLEJCwMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJNFqXg/V3aimJKUmUaqmQEEoSc3qvXFITvT5f5bKw9yk/NVhR6wndL+z/24h1OdRqs76blgH8k116qWNkkDtt0AlSjQOx5qvFYh1UviOjNdRI4WkYONSw+vuavcx+fB6O5JDHNmMhMySKTnmRqTkyhjrch7zaFIWUSV7hsBuxpqmrWDoLWdXbV3eFH3mINA5AoIY/m0bZtzZ7YNgiFWzxQgekpxd0vcTseMnCcXnsAlctdir0FoCZztxMuZjlBjwLTtM6Ry3/48LMM8Z+lw7NMciKLLTGQyU8XmKKSSOh0dGh5Lrlt5GxIIJkH81C0YimWebz8464QPL3RbLnTKg+c=",
        "OrganizationLogoUrl": "https://validator.spid.gov.it/img/idp-logo.png",
        "SingleSignOnServiceUrlPost": "https://demo.spid.gov.it/validator/samlsso",
        "SingleSignOutServiceUrlPost": "https://demo.spid.gov.it/validator/samlsso",
        "SingleSignOnServiceUrlRedirect": "https://demo.spid.gov.it/validator/samlsso",
        "SingleSignOutServiceUrlRedirect": "https://demo.spid.gov.it/validator/samlsso",
        "Type": "DevelopmentProvider"
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
    "AssertionConsumerServiceURL": "https://localhost:5001/signin-spid",
    "AssertionConsumerServiceIndex": 0,
    "AttributeConsumingServiceIndex": 0,
    "RandomIdentityProvidersOrder": false,
    "SecurityLevel": 2,
    "RequestMethod": "Post"
  }
```
La configurazione del certificato del SP avviene specificando nel campo `Source` uno tra i valori `Store/File/Raw/None` (nel caso di `None` non verrà caricato un certificato durante lo startup, ma sarà necessario fornirne uno a runtime, tramite l'uso dei `CustomSpidEvents`, che verranno presentati più nel dettaglio nella sezione successiva) e compilando opportunamente la sezione corrispondente al valore specificato. Le sezioni non usate (quelle cioè corrispondenti agli altri valori) potranno essere tranquillamente eliminate dal file di configurazione, dal momento che non verranno lette.

In alternativa, è possibile configurare tutte le suddette opzioni programmaticamente, dal metodo `AddSpid(options => ...)`.
Gli endpoint di callback per le attività di signin e signout sono impostati di default, rispettivamente, a `/signin-spid` e `/signout-spid` (che, sotto forma di URL assoluta, e quindi comprensivi di schema e hostname, devono essere indicati rispettivamente nei tag `AssertionConsumerService` e `SingleLogoutService` del metadata del SP), ma laddove fosse necessario modificare queste impostazioni, è possibile sovrascriverle (sia da configurazione che da codice) reimpostando le options `CallbackPath` e `RemoteSignOutPath`.
I valori di AssertionConsumerServiceIndex e AssertionConsumerServiceURL sono mutuamente esclusivi, è possibile indicare l'uno o l'altro, ma l'indicazione di entrambi causa la restituzione del codice di errore n.16 da parte dell'IdentityProvider.

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
        context.TokenOptions.SecurityLevel = customConfig.SecurityLevel;
        context.TokenOptions.RequestMethod = customConfig.RequestMethod;

        return base.TokenCreating(context);
    }
    
    public override Task AuthenticationSuccess(AuthenticationSuccessContext context)
    {
        var principal = context.AuthenticationTicket.Principal;
	
	// Recupero dati provenienti da Spid da ClaimsPrincipal
        var spidCode = principal.FindFirst(SpidClaimTypes.SpidCode);
        var name = principal.FindFirst(SpidClaimTypes.Name);
        var surname = principal.FindFirst(SpidClaimTypes.FamilyName);
        var email = principal.FindFirst(SpidClaimTypes.Email);
        var fiscalCode = principal.FindFirst(SpidClaimTypes.FiscalNumber);
        // ............etc........
	
        return base.AuthenticationSuccess(context);
    }

}
```


# Generazione Metadata Service Provider
La libreria è dotata della possibilità di generare dinamicamente dei metadata per Service Provider conformi con i seguenti profili:

- spid-sp-public: Public Spid SP
- spid-sp-private: Private Spid SP
- spid-sp-ag-public-full: Public Spid SP Aggregatore Full
- spid-sp-ag-public-lite: Public Spid SP Aggregatore Lite
- spid-sp-op-public-full: Public Spid SP Gestore Full
- spid-sp-op-public-lite: Public Spid SP Gestore Lite

E' possibile aggiungere nuovi ServiceProvider sia in maniera procedurale, in fase di `Startup`, come segue:

```csharp
.AddSpid(o =>
{
    o.LoadFromConfiguration(Configuration);
    o.ServiceProviders.AddRange(GetServiceProviders(o));
})

......

private List<Authentication.Models.ServiceProviders.ServiceProvider> GetServiceProviders(SpidOptions o)
{
    return new List<Authentication.Models.ServiceProviders.ServiceProvider>(){
	    new Authentication.Models.ServiceProviders.ServiceProviderPublic()
	    {
		FileName = "metadata.xml",
		Certificate = o.Certificate,
		Id = Guid.NewGuid(), // Questa impostazione è solo di esempio, per i metadata reali è necessario mantenere sempre lo stesso Id
		EntityId = "https://spid.asfweb.it/",
		SingleLogoutServiceLocations = new List<SingleLogoutService>() {
		    new SingleLogoutService() {
			Location = "https://localhost:5001/signout-spid",
			ProtocolBinding = ProtocolBinding.POST
		    }
		    ..... // 1 o più
		},
		AssertionConsumerServices = new System.Collections.Generic.List<AssertionConsumerService>() {
		    new AssertionConsumerService() {
			Index = 0,
			IsDefault = true,
			Location = "https://localhost:5001/signin-spid",
			ProtocolBinding = ProtocolBinding.POST
		    }
		    ..... // 1 o più
		},
		AttributeConsumingServices = new System.Collections.Generic.List<AttributeConsumingService>() {
		    new AttributeConsumingService() {
			Index = 0,
			ServiceName = "Service 1",
			ServiceDescription = "Service 1",
			ClaimTypes = new SpidClaimTypes[] {
			    SpidClaimTypes.Name,
			    SpidClaimTypes.FamilyName,
			    SpidClaimTypes.FiscalNumber,
			    SpidClaimTypes.Email
			    ..........
			}
		    },
		    ..... // 1 o più
		},
		OrganizationName = "Organizzazione fittizia per il collaudo",
		OrganizationDisplayName = "Organizzazione fittizia per il collaudo",
		OrganizationURL = "https://www.asfweb.it/",
		VatNumber = "IT01261280620",
		EmailAddress = "info@asfweb.it",
		TelephoneNumber = "+3908241748276",
		IPACode = "__aggrsint"
	    },
.......
```
sia utilizzando una classe che implementa l'interfaccia `IServiceProvidersFactory` e configurandola come segue:

```csharp
.AddSpid(o =>
{
    o.LoadFromConfiguration(Configuration);
})
.AddServiceProvidersFactory<ServiceProvidersFactory>();

........

public class ServiceProvidersFactory : IServiceProvidersFactory
{
	public Task<List<ServiceProvider>> GetServiceProviders()
	    => Task.FromResult(new List<ServiceProvider>() {
		new Authentication.Models.ServiceProviders.ServiceProviderPublicFullAggregator()
		{
..............
```

Infine, per poter esporre gli endpoint dei metadata relativi ai Service Provider registrati, sarà necessario aggiungere la seguente riga:
```csharp
app.AddSpidSPMetadataEndpoints();
```

Tutti i metadata generati vengono automaticamente esposti su endpoint diversi, che hanno come BasePath `/metadata-spid` (ad esempio, un metadata definito con NomeFile = `metadata.xml` verrà esposto sull'endpoint `/metadata-spid/metadata.xml`): il BasePath può essere cambiato, sovrascrivendo la proprietà `ServiceProvidersMetadataEndpointsBasePath` sulle SpidOptions nello `Startup.cs`.

All'interno dell'esempio `1_SimpleSPWebApp` è presente un ServiceProvider di esempio per ogni tipologia di profilo, sia configurato in maniera procedurale, sia tramite `IServiceProvidersFactory`.

# Log Handling
Dalla versione 2.0.0 è possibile specificare un custom LogHandler al fine di implementare la strategia di salvataggio dei Log di Request/Response che si preferisce.
E' sufficiente implementare la seguente classe:

```csharp
public class LogHandler : ILogHandler
{
    public Task LogPostRequest(PostRequest request)
    {
        // Persist your request
    }

    public Task LogPostResponse(PostResponse response)
    {
        // Persist your response
    }

    public Task LogRedirectRequest(RedirectRequest request)
    {
        // Persist your request
    }

    public Task LogRedirectResponse(RedirectResponse response)
    {
        // Persist your response
    }
}
```

ed effettuare l'opportuna registrazione nello Startup come segue:

```csharp
services.AddAuthentication(/* ... */)
                .AddSpid(/* ... */)
                .AddLogHandler<LogHandler>()
                /* add other Spid-related services.... */;
```

# Error Handling
La libreria può, in qualunque fase (sia in fase di creazione della Request sia in fase di gestione della Response), sollevare eccezioni. 

Le eccezioni sollevate sono tutte del tipo `SpidException` la quale contiene 3 proprietà: 

- **Message** : proprietà che contiene il messaggio di errore localizzato di cui, alcuni di questi, sono formulati in accordo con quanto richiesto dalle specifiche SPID: può essere utilizzato per mostrare un messaggio di errore agli utenti finali.
- **SpidErrorCode** : proprietà che contiene i tipi di errore rilevati dalla libreria. I codici da 0 a 111 riguardano le segnalazioni di errori che vengono verificati durante la procedura di onboarding. I codici dal 1000 in poi sono relativi a possibili segnalazioni di errore fatte dalla libreria durante la fase di configurazione o la verifica delle informazioni scambiate nella procedura di autenticazione. Questa proprietà è utile nel caso in cui si volessero creare dei messaggi di errore personalizzati per determinate casistiche che non sono soggette a verifica puntuale durante il processo di onboarding. ESEMPIO: 

  I codici di errore *Anomalia19, Anomalia20, Anomalia21, Anomalia22, Anomalia23 e Anomalia25* viene restituito un messaggio di errore specifico mentre per i restanti codici viene restituito un messaggio generico. Se si vuole personalizzare questo messaggio generico, è necessario fare in modo che risulti chiaro all'utente finale.  
- **Reason** : proprietà che contiene un messaggio di errore localizzato il quale specifica meglio l'origine dell'errore. Questo messaggio fornisce informazioni allo sviluppatore per cui può risultare utile per operazioni di logging.

 É possibile gestire le eccezioni (ad esempio per la visualizzazione) utilizzando il normale flusso previsto per AspNetCore. L'esempio seguente fa uso del middleware di ExceptionHandling di AspNetCore.

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

# eIDAS
Dalla versione 1.3.0 in poi la libreria supporta anche la login con eIDAS. Per utilizzare tale modalità è sufficiente aggiungere la sezione "Eidas" all'interno del file di configurazione, come segue:

```
  "Spid": {
  ......
  },
  "Eidas": {
    "EntityId": "https://sp-proxy.pre.eid.gov.it/spproxy/idpit",
    "Name": "Eidas",
    "OrganizationName": "eIDAS Test/PreProduzione",
    "OrganizationDisplayName": "eIDAS Test/PreProduzione",
    "X509SigningCertificate": "MIIE9DCCA1ygAwIBAgIJALwGssYCzsxcMA0GCSqGSIb3DQEBCwUAMIGpMQswCQYDVQQGEwJJVDEtMCsGA1UECgwkQWdlbnppYSBwZXIgbCdJdGFsaWEgRGlnaXRhbGUgLSBBZ0lEMSwwKgYDVQQLDCNGSUNFUCBQcmUtcHJvZHVjdGlvbiBJbmZyYXN0cnVjdHVyZTE9MDsGA1UEAww0UHVibGljIEFkbWluaXN0cmF0aW9uIFNQIFBST1hZIElEUC1JVCBTQU1MIFNpZ25hdHVyZTAeFw0yMjExMTQxNjEyNDJaFw0yNDExMTMxNjEyNDJaMIGpMQswCQYDVQQGEwJJVDEtMCsGA1UECgwkQWdlbnppYSBwZXIgbCdJdGFsaWEgRGlnaXRhbGUgLSBBZ0lEMSwwKgYDVQQLDCNGSUNFUCBQcmUtcHJvZHVjdGlvbiBJbmZyYXN0cnVjdHVyZTE9MDsGA1UEAww0UHVibGljIEFkbWluaXN0cmF0aW9uIFNQIFBST1hZIElEUC1JVCBTQU1MIFNpZ25hdHVyZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAL+1tL5BHYhUVg5XlUYN95ZL4G+c76u6I1GzqO6io3F+bNhkJ8cU+6s2TuRccskKFaYQX5HYusvKgh/CpgaHWUKtAdHHfLDuAtsM9JR5rh3UelsfFpEc39bQVIuC0mFVoVHrYKLqVyNad8CnuEloJg54aEiWdpirLSYowfKVlUy5exMbaTtqNo7qzVaZf922dxwRrUZz8MHSqbyKfvZPt9Sxfea8GsnEcnKp8aHxge6x8Q3ot8GTPtoebdgXCA4rP6N5kwwVFJ8glpEsST9VahCNcxyEVbKLVfWzELvWn6huPjwG4LPpSC2rSYshFbDTH3VppAlxs75tRM+r0ekv2i8KIp05sgdYkXEGRy6F79SPcsoYVySI1QAyGncrusOAhpFm5ilkPRHlTnmWmXBw/eowSd6uOLg3nLWqDQlRAGVNokKJzgbDN80OHCQiryYUmeu7Hcm2QDjnn4aZD6vO0fL1IWdKC7egsFjEDpN0+WrnXXoFFZDhp4FbVgFPDdwzCwIDAQABox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAYEAUNVv9U/bUwmn+qLrnN+eWAVtXsRBMfPdnbv7tvr8HsTJlvIK65CCHIxSMWs8Efs34DvgR6ZuOcTRvT3cXTfS5plKHI+EWLBFTTm0WloEr2MSI9Lb/Ss7A+MGRzA5HQb8vY7xKel20fHtSqcGLV0qnKc3VRhM0Yh9CBTdOJfpryexMDynlqRf9jxNJD73Rifo7XmIHQcw01D7TVSe/q58V71XuzX4WzAD+bNtDXcjPTCKOJeLHJhuAC9jGfEHwZsuMXYZphXVUa6QbyccRqZDFZagUk6esstexC9m/s3OnmF9nWqDKrQawi1AKGIZhr7mI0s/CzUEXgFvkPdEMvdzaIUF9sG6FNrK8D/NAQVztMduoEwY2p+GbyQysOd9eZgQspQ5S3de5GBsUQpqTuv3nzqKscjMCeKmSFMoJsC5DaRK4fVEXGmZqOniJbeS/C0SmKjtSnIQ5xo8Gy5ZhcRl+FCTCPClABXT6EwMC7Dco6uAA17XNEWRjZK4lnmUNJiq",
    "OrganizationLogoUrl": "https://www.eid.gov.it/assets/img/logo-eIDAS-login.svg",
    "SingleSignOnServiceUrlPost": "https://sp-proxy.pre.eid.gov.it/spproxy/samlsso",
    "SingleSignOutServiceUrlPost": "https://sp-proxy.pre.eid.gov.it/spproxy/samlslo",
    "SingleSignOnServiceUrlRedirect": "https://sp-proxy.pre.eid.gov.it/spproxy/samlsso",
    "SingleSignOutServiceUrlRedirect": "https://sp-proxy.pre.eid.gov.it/spproxy/samlslo",
    "AttributeConsumingServiceIndex": 99 // Or 100
  }
```

All'interno della configurazione dell'IdentityProvider è possibile specificare il valore di `AttributeConsumingServiceIndex` (99 o 100, come riportato nei metadata) da utilizzare per costruire la request, valore che sovrascrive (per eIDAS) il valore di default specificato nella sezione `Spid`.
Per renderizzare il pulsante "Login with eIDAS" è sufficiente aggiungere il seguente codice alla view Razor.

```razor
@using SPID.AspNetCore.Authentication
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
@addTagHelper *, SPID.AspNetCore.Authentication
@{
	ViewData["Title"] = "Login Page";
}
@section styles {
	<style eidas></style>
}
<div class="text-center">
	<h1 class="display-4">Welcome</h1>
	<eidas-button challenge-url="/home/login" size="Medium" circle-image-type="ywb" class="text-left"></eidas-button>
</div>
```

Il tag `eidas-button` prevede, oltre agli attributi già definiti per il pulsante SPID (come `size` e `challenge-url`), un attributo `circle-image-type`, che definisce le diverse tipologie di pulsanti eIDAS che è possibile renderizzare, e i valori che può assumere sono `db, lb, ybw, ywb`.


# Compatibilità con Bootstrap
Se la WebApp utilizza Bootstrap, è necessario aggiungere la seguente classe al fine di visualizzare correttamente il pulsante "Entra con SPID"

```css
.spid-idp-button * {
  box-sizing: content-box;
}
```

# Esempi
All'interno della cartella `samples` è possibile trovare alcune implementazioni esemplificative di webapp che fanno uso della libreria:

- 1_SimpleSPWebApp: semplice webapp AspNetCore MVC che utilizza Spid come sistema di login esterno
- 2_IdentityServer: implementazione di una istanza di IdentityServer4 (che fa da IAM proxy OIDC verso Spid) che utilizza Spid come sistema di login esterna, e una webapp MVC federata con l'istanza di IdentityServer4
- 3_RazorPages: semplice webapp AspNetCore con RazorPages che utilizza Spid come sistema di login esterno

Questi esempi sono solo esemplificativi dell'integrazione con la libreria, non devono essere utilizzati "as-is" in ambienti di produzione.

# Compliance
La libreria è stata oggetto di collaudo da parte di AGID, sia per soluzioni come ServiceProvider che come Aggregatore, ha superato tutti i test di [spid-sp-test](https://github.com/italia/spid-sp-test) (che è integrata in CI, è possibile vedere i log nelle actions), ed è compliant con le direttive specificate negli avvisi SPID.


# Upgrade dalla versione 1.x alla 2.x
A partire dalla versione 2.0.0 è stato introdotto il discovery automatizzato degli IdentityProvider di produzione, non è più necessario quindi includerli nelle settings, ma verrà utilizzato l'endpoint dello SPID Registry per il discovery.
Inoltre è stata migliorata la gestione dei Log e degli SpidEvents.

Di seguito le modifiche agli appsettings:
- Sezione Eidas e "IdentityProvider" di Sviluppo/Collaudo
  - Aggiunte le property "EntityId", "X509SigningCertificate", "SingleSignOnServiceUrlPost", "SingleSignOutServiceUrlPost", "SingleSignOnServiceUrlRedirect", "SingleSignOutServiceUrlRedirect"
  - Eliminate le property "OrganizationUrlMetadata", "OrganizationUrl", "SingleSignOnServiceUrl", "SingleSignOutServiceUrl", "Method", "SecurityLevel"
- Eliminati gli IdentityProvider di produzione, il discovery verrà effettuato in automatico dalla libreria
- Sezione root, aggiunte le property "SecurityLevel" (default "2"), "RequestMethod" (default "POST"), "IdPRegistryURL" (default "https://registry.spid.gov.it/entities-idp?&output=json")

Di seguito le modifiche agli SpidEvents:
- Aggiunte le property "SecurityLevel" e "RequestMethod" all'oggetto "SecurityTokenCreatingOptions", che viene iniettato nello SpidEvent "OnTokenCreating". Effettuando l'override di queste nuove property è possibile specificare, per request, il SecurityLevel e il RequestMethod desiderati. In caso contrario verranno utilizzati i valori di default o quelli specificati nella root della sezione di settings riportati sopra.

E' stata aggiunta la possibilità di specificare un custom LogHandler, come riportato nella sezione dedicata.

# Authors
* [Daniele Giallonardo](https://github.com/danielegiallonardo) (maintainer) - [Stefano Mostarda](https://github.com/sm15455)
