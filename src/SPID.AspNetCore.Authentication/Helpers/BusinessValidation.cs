using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Runtime.CompilerServices;

namespace SPID.AspNetCore.Authentication.Helpers
{
    internal static class BusinessValidation
    {
        public static void Argument<T>(T input, string error, [CallerArgumentExpression("input")] string inputName = "") where T : class
        {
            if (input is string && string.IsNullOrWhiteSpace(input.ToString()) || input == default(T))
                throw new SpidException(String.Format(ErrorLocalization.ArgumentNull, inputName), error, SpidErrorCode.ArgumentNull);
        }

        public static void ValidationCondition(Func<bool> condition, SpidException error)
        {
            if (condition())
            {
                throw error;
            }
        }

        public static void ValidationTry(Action action, string error, SpidErrorCode spidErrorCode)
        {
            try
            {
                action();

            }
            catch (Exception e)
            {
                throw new SpidException(ErrorLocalization.GenericMessage, error, spidErrorCode, e);
            }
        }

        public static void ValidationNotNull(object input, SpidException error)
        {
            if (input == null)
            {
                throw error;
            }
        }

        public static void ValidationNotNullNotWhitespace(string input, SpidException error)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                throw error;
            }
        }

        public static T ValidationNotNullNotEmpty<T>(T input, SpidException error) where T : class, new()
        {
            var instance = new T();
            if (input == default(T)) throw error;
            return input;
        }
    }
}
