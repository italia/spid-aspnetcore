using System.Collections.Generic;

namespace SPID.AspNetCore.Authentication.Models
{
    public sealed class SpidClaimTypes
    {
        private static Dictionary<string, SpidClaimTypes> _types = new Dictionary<string, SpidClaimTypes>() {
            { nameof(Name), new SpidClaimTypes(nameof(Name)) },
            { nameof(FamilyName), new SpidClaimTypes(nameof(FamilyName)) },
            { nameof(FiscalNumber), new SpidClaimTypes(nameof(FiscalNumber)) },
            { nameof(Email), new SpidClaimTypes(nameof(Email)) },
            { nameof(DigitalAddress), new SpidClaimTypes(nameof(DigitalAddress)) },
            { nameof(Mail), new SpidClaimTypes(nameof(Mail)) },
            { nameof(Surname), new SpidClaimTypes(nameof(Surname)) },
            { nameof(Firstname), new SpidClaimTypes(nameof(Firstname)) },
            { nameof(Address), new SpidClaimTypes(nameof(Address)) },
            { nameof(CompanyName), new SpidClaimTypes(nameof(CompanyName)) },
            { nameof(CountyOfBirth), new SpidClaimTypes(nameof(CountyOfBirth)) },
            { nameof(DateOfBirth), new SpidClaimTypes(nameof(DateOfBirth)) },
            { nameof(ExpirationDate), new SpidClaimTypes(nameof(ExpirationDate)) },
            { nameof(Gender), new SpidClaimTypes(nameof(Gender)) },
            { nameof(IdCard), new SpidClaimTypes(nameof(IdCard)) },
            { nameof(IvaCode), new SpidClaimTypes(nameof(IvaCode)) },
            { nameof(MobilePhone), new SpidClaimTypes(nameof(MobilePhone)) },
            { nameof(PlaceOfBirth), new SpidClaimTypes(nameof(PlaceOfBirth)) },
            { nameof(RegisteredOffice), new SpidClaimTypes(nameof(RegisteredOffice)) },
            { nameof(SpidCode), new SpidClaimTypes(nameof(SpidCode)) }
        };

        private SpidClaimTypes(string value)
        {
            Value = value;
        }

        public string Value { get; private set; }

        public static SpidClaimTypes Name { get { return _types[nameof(Name)]; } }
        public static SpidClaimTypes FamilyName { get { return _types[nameof(FamilyName)]; } }
        public static SpidClaimTypes FiscalNumber { get { return _types[nameof(FiscalNumber)]; } }
        public static SpidClaimTypes Email { get { return _types[nameof(Email)]; } }
        public static SpidClaimTypes DigitalAddress { get { return _types[nameof(DigitalAddress)]; } }
        public static SpidClaimTypes Mail { get { return _types[nameof(Mail)]; } }
        public static SpidClaimTypes Surname { get { return _types[nameof(Surname)]; } }
        public static SpidClaimTypes Firstname { get { return _types[nameof(Firstname)]; } }
        public static SpidClaimTypes Address { get { return _types[nameof(Address)]; } }
        public static SpidClaimTypes CompanyName { get { return _types[nameof(CompanyName)]; } }
        public static SpidClaimTypes CountyOfBirth { get { return _types[nameof(CountyOfBirth)]; } }
        public static SpidClaimTypes DateOfBirth { get { return _types[nameof(DateOfBirth)]; } }
        public static SpidClaimTypes ExpirationDate { get { return _types[nameof(ExpirationDate)]; } }
        public static SpidClaimTypes Gender { get { return _types[nameof(Gender)]; } }
        public static SpidClaimTypes IdCard { get { return _types[nameof(IdCard)]; } }
        public static SpidClaimTypes IvaCode { get { return _types[nameof(IvaCode)]; } }
        public static SpidClaimTypes MobilePhone { get { return _types[nameof(MobilePhone)]; } }
        public static SpidClaimTypes PlaceOfBirth { get { return _types[nameof(PlaceOfBirth)]; } }
        public static SpidClaimTypes RegisteredOffice { get { return _types[nameof(RegisteredOffice)]; } }
        public static SpidClaimTypes SpidCode { get { return _types[nameof(SpidCode)]; } }
    }
}
