using Candlewire.Identity.Server.Contexts;
using Candlewire.Identity.Server.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    /// <summary>
    /// Caching data server side (for use when not logged in)
    /// Prerequisite (app.UseSessionManager in startup)
    /// </summary>
    public class SessionManager
    {
        public static String SessionCode = ".AspNetCore.Persistence.YMVGG149DF2";
        private IHttpContextAccessor RequestAccessor { get; set; }
        public PersistenceDbContext PersistenceContext { get; set; }

        public SessionManager(IHttpContextAccessor requestAccessor, PersistenceDbContext persistenceContext)
        {
            RequestAccessor = requestAccessor;
            PersistenceContext = persistenceContext;
        }

        public async Task AddAsync(String key, Object value, DateTime expiration)
        {
            var persistenceCode = SessionCode;
            var persistenceKey = key;
            var persistenceObject = value;
            var persistenceExpiration = expiration;
            var persistenceToken = RequestAccessor.HttpContext.Request.Cookies[persistenceCode];
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

        public async Task RemoveAsync(String key)
        {
            var persistenceCode = SessionCode;
            var persistenceKey = key;
            var persistenceToken = RequestAccessor.HttpContext.Request.Cookies[persistenceCode];
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

        public async Task ClearAsync()
        {
            var persistenceCode = SessionCode;
            var persistenceToken = RequestAccessor.HttpContext.Request.Cookies[persistenceCode];
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

        public async Task<T> GetAsync<T>(String key, Boolean? remove = false)
        {
            var persistenceCode = SessionCode;
            var persistenceKey = key;
            var persistenceDate = DateTime.UtcNow;
            var persistenceToken = RequestAccessor.HttpContext.Request.Cookies[persistenceCode];
            if (persistenceToken != null)
            {
                var persistenceItem = await PersistenceContext.PersistenceItems.FirstOrDefaultAsync(a => a.PersistenceToken == persistenceToken && a.PersistenceKey == persistenceKey && a.PersistenceExpiration > persistenceDate);
                if (persistenceItem != null)
                {
                    if (remove == true)
                    {
                        PersistenceContext.PersistenceItems.Remove(persistenceItem);
                        await PersistenceContext.SaveChangesAsync();
                    }
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
