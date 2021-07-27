using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Routing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Attributes
{
    public class RequireParameterAttribute : ActionMethodSelectorAttribute
    {
        public string[] ParameterNames { get; private set; }

        public MatchMode Mode { get; set; }

        public RequireParameterAttribute(string parameterName)
        {
            ParameterNames = new[] { parameterName };
            Mode = MatchMode.All;
        }

        public RequireParameterAttribute(params string[] parameterNames)
        {
            ParameterNames = parameterNames;
            Mode = MatchMode.All;
        }

        public override Boolean IsValidForRequest(RouteContext routeContext, ActionDescriptor actionDescriptor)
        {
            switch (Mode)
            {
                case MatchMode.All:
                default:
                    return ParameterNames.All(p => routeContext.HttpContext.Request.Query.ContainsKey(p));
                case MatchMode.Any:
                    return ParameterNames.Any(p => routeContext.HttpContext.Request.Query.ContainsKey(p));
                case MatchMode.None:
                    return !ParameterNames.Any(p => routeContext.HttpContext.Request.Query.ContainsKey(p));
            }
        }

        public enum MatchMode : int
        {
            All,
            Any,
            None
        }
    }
}
