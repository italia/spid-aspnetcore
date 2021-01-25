using SPID.AspNetCore.Authentication.Resources;
using System;

namespace SPID.AspNetCore.Authentication.Helpers
{
    public static class BusinessValidation
    {
        public static void Argument<T>(T input, string error) where T : class
        {
            if (input is string && string.IsNullOrWhiteSpace(input.ToString()) || input == default(T)) throw new ArgumentNullException(error);
        }

        public static void ValidationCondition(Func<bool> condition, string error)
        {
            if (condition())
            {
                throw new Exception(error);
            }
        }

        public static void ValidationTry(Action action, string error)
        {
            try
            {
                action();

            }
            catch (Exception)
            {
                throw new Exception(error);
            }
        }

        public static void ValidationNotNull(object input, string nameVariable)
        {
            if (input == null)
            {
                throw new Exception(string.Format(ErrorLocalization.NotSpecified, nameVariable));
            }
        }

        public static void ValidationNotNullNotWhitespace(string input, string nameVariable)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                throw new Exception(string.Format(ErrorLocalization.NotSpecified, nameVariable));
            }
        }

        public static T ValidationNotNullNotEmpty<T>(T input, string nameVariable) where T : class, new()
        {
            var instance = new T();
            if (input == default(T)) throw new Exception(string.Format(ErrorLocalization.NotDefined, nameVariable));
            return input;
        }
    }
}
