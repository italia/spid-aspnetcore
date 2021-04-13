using System;
using System.Collections.Generic;
using System.Text;

namespace SPID.AspNetCore.Authentication.Models
{
    public sealed class SpidClaimTypes
    {
        public static string Name = nameof(Name);
        public static string FamilyName = nameof(FamilyName);
        public static string FiscalNumber = nameof(FiscalNumber);
        public static string Email = nameof(Email);
        public static string DigitalAddress = nameof(DigitalAddress);
        public static string Mail = nameof(Mail);
        public static string Surname = nameof(Surname);
        public static string Firstname = nameof(Firstname);
        public static string Address = nameof(Address);
        public static string CompanyName = nameof(CompanyName);
        public static string CountyOfBirth = nameof(CountyOfBirth);
        public static string DateOfBirth = nameof(DateOfBirth);
        public static string ExpirationDate = nameof(ExpirationDate);
        public static string Gender = nameof(Gender);
        public static string IdCard = nameof(IdCard);
        public static string IvaCode = nameof(IvaCode);
        public static string MobilePhone = nameof(MobilePhone);
        public static string PlaceOfBirth = nameof(PlaceOfBirth);
        public static string RegisteredOffice = nameof(RegisteredOffice);
        public static string SpidCode = nameof(SpidCode);
    }
}
