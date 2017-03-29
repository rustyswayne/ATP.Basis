namespace ATP.Basis
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Text.RegularExpressions;

    /// <summary>
    /// Extension methods for Strings.
    /// </summary>
    public static partial class Extensions
    {

        /// <summary>
        /// Replaces \ with / in a path.
        /// </summary>
        /// <param name="value">
        /// The value to replace backslashes.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string EnsureForwardSlashes(this string value)
        {
            return value.Replace("\\", "/");
        }

        /// <summary>
        /// Replaces \ with / in a path.
        /// </summary>
        /// <param name="value">
        /// The value to replace forward slashes.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string EnsureBackSlashes(this string value)
        {
            return value.Replace("/", "\\");
        }


        public static string TrimStart(this string value, string forRemoving)
        {
            if (string.IsNullOrEmpty(value)) return value;
            if (string.IsNullOrEmpty(forRemoving)) return value;

            while (value.StartsWith(forRemoving))
            {
                value = value.Substring(forRemoving.Length);
            }
            return value;
        }

        public static string EnsureStartsWith(this string input, string toStartWith)
        {
            if (input.StartsWith(toStartWith)) return input;
            return toStartWith + input.TrimStart(toStartWith);
        }

        public static string EnsureStartsWith(this string input, char value)
        {
            return input.StartsWith(value.ToString()) ? input : value + input;
        }

        /// <summary>
        /// Ensures a string both starts and ends with a character.
        /// </summary>
        /// <param name="input">
        /// The input string.
        /// </param>
        /// <param name="value">
        /// The char value to assert
        /// </param>
        /// <returns>
        /// The asserted string.
        /// </returns>
        public static string EnsureStartsAndEndsWith(this string input, char value)
        {
            return input.EnsureStartsWith(value).EnsureEndsWith(value);
        }

        /// <summary>
        /// Ensures a string ends with a character.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <param name="value">
        /// The value.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string EnsureEndsWith(this string input, char value)
        {
            return input.EndsWith(value.ToString()) ? input : input + value;
        }

        /// <summary>
        /// Ensures a string ends with a string.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <param name="toEndWith">
        /// The to end with.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string EnsureEndsWith(this string input, string toEndWith)
        {
            return input.EndsWith(toEndWith) ? input : input + toEndWith;
        }

        /// <summary>
        /// Ensures a string does not end with a character.
        /// </summary>
        /// <param name="input">
        /// The input string.
        /// </param>
        /// <param name="value">
        /// The char value to assert
        /// </param>
        /// <returns>
        /// The asserted string.
        /// </returns>
        public static string EnsureNotEndsWith(this string input, char value)
        {
            return !input.EndsWith(value.ToString()) ? input :
                input.Remove(input.LastIndexOf(value), 1);
        }

        /// <summary>
        /// Ensures a string does not start with a character.
        /// </summary>
        /// <param name="input">
        /// The input string.
        /// </param>
        /// <param name="value">
        /// The char value to assert
        /// </param>
        /// <returns>
        /// The asserted string.
        /// </returns>
        public static string EnsureNotStartsWith(this string input, char value)
        {
            return !input.StartsWith(value.ToString()) ? input : input.Remove(0, 1);
        }

        /// <summary>
        /// Ensures a string does not start or end with a character.
        /// </summary>
        /// <param name="input">
        /// The input string.
        /// </param>
        /// <param name="value">
        /// The char value to assert
        /// </param>
        /// <returns>
        /// The asserted string.
        /// </returns>
        public static string EnsureNotStartsOrEndsWith(this string input, char value)
        {
            return input.EnsureNotStartsWith(value).EnsureNotEndsWith(value);
        }

        /// <summary>Inspects a string to determine if it is null or white space.</summary>
        /// <param name="str">The string to inspect.</param>
        /// <returns>A value indicating whether or not the string was null or white space.</returns>
        public static bool IsNullOrWhiteSpace(this string str)
        {
            return (str == null) || (str.Trim().Length == 0);
        }

        /// <summary>
        /// Inspects a string to determine if it is null or white space, if it is, will return the default value.
        /// </summary>
        /// <param name="str">
        /// The string to inspect.
        /// </param>
        /// <param name="defaultValue">
        /// The default value.
        /// </param>
        /// <returns>
        /// The original string or the default value.
        /// </returns>
        public static string IfNullOrWhiteSpace(this string str, string defaultValue)
        {
            return str.IsNullOrWhiteSpace() ? defaultValue : str;
        }

        /// <summary>
        /// Converts an integer to an invariant formatted string
        /// </summary>
        /// <param name="str">The source string</param>
        /// <returns>The string representation of the integer</returns>
        public static string ToInvariantString(this int str)
        {
            return str.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Removes special characters.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <param name="replacement">
        /// The replacement.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        internal static string ReplaceNonAlphanumericChars(this string input, char replacement)
        {
            var inputArray = input.ToCharArray();
            var outputArray = new char[input.Length];
            for (var i = 0; i < inputArray.Length; i++)
            {
                outputArray[i] = char.IsLetterOrDigit(inputArray[i]) ? inputArray[i] : replacement;
            }
                
            return new string(outputArray);
        }

        /// <summary>
        /// The convert to slug.
        /// </summary>
        /// <param name="value">
        /// The value.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        internal static string ConvertToSlug(this string value)
        {
            return RemoveSpecialCharacters(value).SafeEncodeUrlSegments().ToLowerInvariant().EnsureNotStartsOrEndsWith('/');
        }

        /// <summary>
        /// Encodes url segments.
        /// </summary>
        /// <param name="urlPath">
        /// The url path.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        /// <seealso cref="https://github.com/Shandem/Articulate/blob/master/Articulate/StringExtensions.cs"/>
        internal static string SafeEncodeUrlSegments(this string urlPath)
        {
            
            return string.Join(
                "/",
                urlPath.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x =>
                    {
                        var urlEncode = WebUtility.UrlEncode(x);
                        return urlEncode != null ? urlEncode.Replace("+", "-") : null;
                    })
                    .Where(x => x != null)

                    //// we are not supporting dots in our URLs it's just too difficult to
                    //// support across the board with all the different config options
                    .Select(x => x.Replace('.', '-')));
        }

        /// <summary>
        /// The remove special characters.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        internal static string RemoveSpecialCharacters(string input)
        {
            var regex = new Regex("(?:[^a-z0-9 ]|(?<=['\"])s)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            return regex.Replace(input, string.Empty);
        }
    }
}
