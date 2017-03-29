// ReSharper disable All
namespace ATP.Basis.Logging
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Reflection;

    using log4net;
    using log4net.Config;

    /// <summary>
    /// The logger.
    /// </summary>
    /// <seealso cref="https://github.com/umbraco/Umbraco-CMS/blob/dev-v7/src/Umbraco.Core/Logging/Logger.cs"/>
    public class Logger : ILogger
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Logger"/> class.
        /// </summary>
        /// <param name="log4NetConfigFile">
        /// The <see cref="FileInfo"/> for the log4net.config.
        /// </param>
        public Logger(FileInfo log4NetConfigFile)
            : this()
        {
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(logRepository, log4NetConfigFile);
        }

        /// <summary>
        /// Prevents a default instance of the <see cref="Logger"/> class from being created.
        /// </summary>
        private Logger()
        {

            log4net.GlobalContext.Properties["processId"] = Process.GetCurrentProcess().Id;
            
            // TODO 
            // log4net.GlobalContext.Properties["appDomainId"] = AppDomain.CurrentDomain.Id;
        }

        /// <summary>
        /// Creates a logger with the default log4net configuration discovered (i.e. from the web.config)
        /// </summary>
        /// <returns>The <see cref="Logger"/></returns>
        public static Logger CreateWithDefaultLog4NetConfiguration()
        {
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            log4net.Config.XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));
            return new Logger();
        }
        
        /// <inheritdoc />
        public void Error(Type callingType, string message, Exception exception)
        {
            var logger = LogManager.GetLogger(callingType);
            if (logger != null) logger.Error(message, exception);
        }

        /// <inheritdoc />
        public void Warn(Type callingType, string message, params Func<object>[] formatItems)
        {
            var logger = LogManager.GetLogger(callingType);
            if (logger == null || logger.IsWarnEnabled == false) return;
            logger.WarnFormat(message, formatItems.Select(x => x.Invoke()).ToArray());
        }

        /// <inheritdoc />
        public void WarnWithException(Type callingType, string message, Exception e, params Func<object>[] formatItems)
        {

            if (callingType == null) throw new ArgumentNullException(nameof(callingType));
            if (e == null) throw new ArgumentNullException(nameof(e));
            if (message.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(message));

            var logger = LogManager.GetLogger(callingType);
            if (logger == null || logger.IsWarnEnabled == false) return;
            var executedParams = formatItems.Select(x => x.Invoke()).ToArray();
            logger.WarnFormat(message + ". Exception: " + e, executedParams);
        }

        /// <inheritdoc />
        public void Info(Type callingType, Func<string> generateMessage)
        {
            var logger = LogManager.GetLogger(callingType);
            if (logger == null || logger.IsInfoEnabled == false) return;
            logger.Info(generateMessage.Invoke());
        }

        /// <inheritdoc />
        public void Info(Type type, string generateMessageFormat, params Func<object>[] formatItems)
        {
            var logger = LogManager.GetLogger(type);
            if (logger == null || logger.IsInfoEnabled == false) return;
            var executedParams = formatItems.Select(x => x.Invoke()).ToArray();
            logger.InfoFormat(generateMessageFormat, executedParams);
        }

        /// <inheritdoc />
        public void Debug(Type callingType, Func<string> generateMessage)
        {
            var logger = LogManager.GetLogger(callingType);
            if (logger == null || logger.IsDebugEnabled == false) return;
            logger.Debug(generateMessage.Invoke());
        }

        /// <inheritdoc />
        public void Debug(Type type, string generateMessageFormat, params Func<object>[] formatItems)
        {
            var logger = LogManager.GetLogger(type);
            if (logger == null || logger.IsDebugEnabled == false) return;
            var executedParams = formatItems.Select(x => x.Invoke()).ToArray();
            logger.DebugFormat(generateMessageFormat, executedParams);
        }


        /// <summary>
        /// Gets a logger for a specific type.
        /// </summary>
        /// <typeparam name="T">
        /// The type to pass log4net's LogManager
        /// </typeparam>
        /// <returns>
        /// The <see cref="ILog"/>.
        /// </returns>
        internal ILog LoggerFor<T>()
        {
            return LogManager.GetLogger(typeof(T));
        }

        /// <summary>
        /// Returns a logger for the object's type
        /// </summary>
        /// <param name="getTypeFromInstance">The object to be used for type inference.</param>
        /// <returns>The <see cref="ILog"/></returns>
        internal ILog LoggerFor(object getTypeFromInstance)
        {
            if (getTypeFromInstance == null) throw new ArgumentNullException("getTypeFromInstance");

            return LogManager.GetLogger(getTypeFromInstance.GetType());
        }
    }
}
