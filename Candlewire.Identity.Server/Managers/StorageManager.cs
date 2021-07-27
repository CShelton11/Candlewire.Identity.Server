using Candlewire.Identity.Server.Contexts;
using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    /// <summary>
    /// Caching data server side (for use when logged in)
    /// </summary>
    public class StorageManager
    {
        private PersistenceDbContext PersistenceContext { get; set; }

        public StorageManager(PersistenceDbContext persistenceContext)
        {
            PersistenceContext = persistenceContext;
        }

        public async Task AddAsync(ApplicationUser user, String key, Object value, DateTime expiration)
        {
            var code = "UserStorageCode";
            var token = (code + user.Id.ToString()).Encrypt();
            await AddAsync(token, key, value, expiration);
        }

        public async Task RemoveAsync(ApplicationUser user, String key)
        {
            var code = "UserStorageCode";
            var token = (code + user.Id.ToString()).Encrypt();
            await RemoveAsync(token, key);
        }

        public async Task ClearAsync(ApplicationUser user)
        {
            var code = "UserStorageCode";
            var token = (code + user.Id.ToString()).Encrypt();
            await ClearAsync(token);
        }

        public async Task<T> GetAsync<T>(ApplicationUser user, String key)
        {
            var code = "UserStorageCode";
            var token = (code + user.Id.ToString()).Encrypt();
            var result = await GetAsync<T>(token, key);
            return result;
        }

        private async Task AddAsync(String token, String key, Object value, DateTime expiration)
        {
            var persistenceToken = token;
            var persistenceKey = key;
            var persistenceObject = value;
            var persistenceExpiration = expiration;
            if (persistenceToken != null)
            {
                var persistenceItem = PersistenceContext.PersistenceItems.FirstOrDefault(a => a.PersistenceToken == persistenceToken && a.PersistenceKey == persistenceKey);
                if (persistenceObject == null)
                {
                    if (persistenceItem != null)
                    {
                        PersistenceContext.PersistenceItems.Remove(persistenceItem);
                        await PersistenceContext.SaveChangesAsync();
                    }
                }
                else
                {
                    if (persistenceItem == null)
                    {
                        persistenceItem = new PersistenceItem();
                        persistenceItem.PersistenceToken = persistenceToken;
                        persistenceItem.PersistenceKey = persistenceKey;
                        persistenceItem.PersistenceExpiration = persistenceExpiration;
                        persistenceItem.PersistenceData = JsonConvert.SerializeObject(persistenceObject).Encrypt();
                        PersistenceContext.PersistenceItems.Add(persistenceItem);
                        await PersistenceContext.SaveChangesAsync();
                    }
                    else
                    {
                        persistenceItem.PersistenceExpiration = persistenceExpiration;
                        persistenceItem.PersistenceData = JsonConvert.SerializeObject(persistenceObject).Encrypt();
                        await PersistenceContext.SaveChangesAsync();
                    }
                }
            }
        }

        private async Task RemoveAsync(String token, String key)
        {
            var persistenceToken = token;
            var persistenceKey = key;
            if (persistenceToken != null)
            {
                var persistenceItem = PersistenceContext.PersistenceItems.FirstOrDefault(a => a.PersistenceToken == persistenceToken && a.PersistenceKey == persistenceKey);
                if (persistenceItem != null)
                {
                    PersistenceContext.PersistenceItems.Remove(persistenceItem);
                    await PersistenceContext.SaveChangesAsync();
                }
            }
        }

        private async Task ClearAsync(String token)
        {
            var persistenceToken = token;
            if (persistenceToken != null)
            {
                var persistenceItems = PersistenceContext.PersistenceItems.Where(a => a.PersistenceToken == persistenceToken).ToList();

                for (var i = 0; i < persistenceItems.Count; i++)
                {
                    var persistenceItem = persistenceItems[i];
                    PersistenceContext.PersistenceItems.Remove(persistenceItem);
                    await PersistenceContext.SaveChangesAsync();
                }
            }
        }

        public async Task<T> GetAsync<T>(String token, String key)
        {
            var persistenceToken = token;
            var persistenceKey = key;
            var persistenceDate = DateTime.UtcNow;
            if (persistenceToken != null)
            {
                var persistenceItem = await PersistenceContext.PersistenceItems.FirstOrDefaultAsync(a => a.PersistenceToken == persistenceToken && a.PersistenceKey == persistenceKey && a.PersistenceExpiration > persistenceDate);
                if (persistenceItem != null)
                {
                    return JsonConvert.DeserializeObject<T>(persistenceItem.PersistenceData.Decrypt());
                }
                else
                {
                    return default(T);
                }
            }
            else
            {
                return default(T);
            }
        }

    }
}
