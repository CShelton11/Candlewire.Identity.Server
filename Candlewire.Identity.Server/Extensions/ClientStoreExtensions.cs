using System;
using System.Threading.Tasks;
using IdentityServer4.Stores;

namespace Candlewire.Identity.Server.Extensions
{
    public static class ClientStoreExtensions
    {
        /// <summary>
        /// Determines whether the client is configured to use PKCE.
        /// </summary>
        /// <param name="store">The store.</param>
        /// <param name="client_id">The client identifier.</param>
        /// <returns></returns>
        public static async Task<Boolean> IsPkceClientAsync(this IClientStore store, String client_id)
        {
            if (!String.IsNullOrWhiteSpace(client_id))
            {
                var client = await store.FindEnabledClientByIdAsync(client_id);
                return client?.RequirePkce == true;
            }
            return false;
        }
    }
}
