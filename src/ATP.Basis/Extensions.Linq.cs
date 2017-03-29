namespace ATP.Basis
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// LINQ extensions.
    /// </summary>
    public static partial class Extensions
    {
        /// <summary>
        /// Gets a distinct collection.
        /// </summary>
        /// <param name="source">
        /// The source.
        /// </param>
        /// <param name="keySelector">
        /// The selector for the key.
        /// </param>
        /// <typeparam name="TSource">
        /// The type of the source objects
        /// </typeparam>
        /// <typeparam name="TKey">
        /// The type of the keys
        /// </typeparam>
        /// <returns>
        /// The <see cref="IEnumerable{TSource}"/>.
        /// </returns>
        public static IEnumerable<TSource> DistinctBy<TSource, TKey>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector)
        {
            var seenKeys = new HashSet<TKey>();
            foreach (var element in source)
            {
                if (seenKeys.Add(keySelector(element)))
                {
                    yield return element;
                }
            }
        }
    }
}
