using Microsoft.Extensions.Logging;
using System;

namespace SPID.AspNetCore.Authentication
{
    internal static class LoggingExtensions
    {
        private static readonly Action<ILogger, Exception> _exceptionProcessingMessage;
        private static readonly Action<ILogger, string, Exception> _malformedRedirectUri;
        private static readonly Action<ILogger, Exception> _remoteSignOutHandledResponse;
        private static readonly Action<ILogger, Exception> _remoteSignOutFailed;
        private static readonly Action<ILogger, Exception> _remoteSignOutSkipped;
        private static readonly Action<ILogger, Exception> _remoteSignOut;

        static LoggingExtensions()
        {
            _exceptionProcessingMessage = LoggerMessage.Define(
                eventId: 3,
                logLevel: LogLevel.Error,
                formatString: "Exception occurred while processing message.");
            _malformedRedirectUri = LoggerMessage.Define<string>(
                eventId: 4,
                logLevel: LogLevel.Warning,
                formatString: "The sign-out redirect URI '{0}' is malformed.");
            _remoteSignOutHandledResponse = LoggerMessage.Define(
               eventId: 5,
               logLevel: LogLevel.Debug,
               formatString: "RemoteSignOutContext.HandledResponse");
            _remoteSignOutSkipped = LoggerMessage.Define(
               eventId: 6,
               logLevel: LogLevel.Debug,
               formatString: "RemoteSignOutContext.Skipped");
            _remoteSignOutFailed = LoggerMessage.Define(
               eventId: 7,
               logLevel: LogLevel.Error,
               formatString: "RemoteSignOutContext.Failed");
            _remoteSignOut = LoggerMessage.Define(
               eventId: 8,
               logLevel: LogLevel.Information,
               formatString: "Remote signout request processed.");
        }

        public static void ExceptionProcessingMessage(this ILogger logger, Exception ex)
        {
            _exceptionProcessingMessage(logger, ex);
        }

        public static void MalformedRedirectUri(this ILogger logger, string uri)
        {
            _malformedRedirectUri(logger, uri, null);
        }

        public static void RemoteSignOutHandledResponse(this ILogger logger)
        {
            _remoteSignOutHandledResponse(logger, null);
        }

        public static void RemoteSignOutSkipped(this ILogger logger)
        {
            _remoteSignOutSkipped(logger, null);
        }

        public static void RemoteSignOutFailed(this ILogger logger)
        {
            _remoteSignOutFailed(logger, null);
        }

        public static void RemoteSignOut(this ILogger logger)
        {
            _remoteSignOut(logger, null);
        }
    }
}
