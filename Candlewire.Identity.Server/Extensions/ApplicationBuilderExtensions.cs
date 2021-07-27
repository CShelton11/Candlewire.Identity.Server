using Candlewire.Identity.Server.Managers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Extensions
{
    public static class ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseRequestForwarding(this IApplicationBuilder builder)
        {
            builder.UseForwardedHeaders(new ForwardedHeadersOptions() { ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto });
            builder.Use((context, next) =>
            {
                if (context.Request.Scheme.Equals("https", StringComparison.CurrentCultureIgnoreCase) == false)
                {
                    var key = "x-forwarded-proto";
                    var url = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
                    var forwarded = context.Request.Headers.Where(a => a.Key.ToLower() == key).Count() > 0;
                    var protocol = forwarded == false ? "http" : context.Request.Headers.FirstOrDefault(a => a.Key == key).Value.ToString().ToLower();
                    if (protocol.Equals("https", StringComparison.CurrentCultureIgnoreCase) == true)
                    {
                        context.Request.Scheme = protocol;
                        context.Request.Protocol = protocol;
                        context.Request.IsHttps = true;
                    }
                }
                return next.Invoke();
            });
            return builder;
        }

        public static IApplicationBuilder UseSessionManager(this IApplicationBuilder builder)
        {
            builder.Use((context, next) =>
            {
                var sessionCode = SessionManager.SessionCode;
                var sessionCookie = context.Request.Cookies[sessionCode];

                if (sessionCookie == null)
                {
                    var sessionExpiration = DateTime.UtcNow.AddMinutes(120);
                    var sessionToken = Guid.NewGuid().ToString().Encrypt();
                    context.Response.Cookies.Append(sessionCode, sessionToken, new CookieOptions() { Expires = sessionExpiration });
                }
                else
                {
                    var sessionToken = sessionCookie.ToString();
                    var sessionExpiration = DateTime.UtcNow.AddMinutes(120);
                    context.Response.Cookies.Append(sessionCode, sessionToken, new CookieOptions() { Expires = sessionExpiration });
                }

                return next.Invoke();
            });
            return builder;
        }
    }
}
