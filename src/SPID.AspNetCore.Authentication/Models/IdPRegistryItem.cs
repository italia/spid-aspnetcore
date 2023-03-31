using System.Collections.Generic;

public class Extensions
{
    public List<string> supported_acr { get; set; }
    public List<string> supported_purpose { get; set; }
}

public class IdPRegistryName
{
    public string entity_id { get; set; }
    public string file_name { get; set; }
    public string file_hash { get; set; }
    public string code { get; set; }
    public List<string> signing_certificate_x509 { get; set; }
    public string organization_name { get; set; }
    public string organization_display_name { get; set; }
    public List<IdPSingleLogoutService> single_logout_service { get; set; }
    public List<IdPSingleSignOnService> single_sign_on_service { get; set; }
    public List<string> attribute { get; set; }
    public Extensions extensions { get; set; }
    public string create_date { get; set; }
    public string lastupdate_date { get; set; }
    public object delete_date { get; set; }
    public string _deleted { get; set; }
    public string _disabled { get; set; }
    public string logo_uri { get; set; }
    public string registry_link { get; set; }
}

public class IdPSingleLogoutService
{
    public string Binding { get; set; }
    public string Location { get; set; }
}

public class IdPSingleSignOnService
{
    public string Binding { get; set; }
    public string Location { get; set; }
}

