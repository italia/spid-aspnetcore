using ObjectsComparer;
using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication
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

        public static async void ValidationAsync(Func<Task<bool>> condition, string error)
        {
            if (await condition())
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
            var compare = new Comparer();
            if (compare.Compare(input, instance)) throw new Exception(string.Format(ErrorLocalization.NotSpecified, nameVariable));
            else if (input == default(T)) throw new Exception(string.Format(ErrorLocalization.NotDefined, nameVariable));
            return input;
        }



    }
}
