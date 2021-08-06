using Microsoft.AspNetCore.Mvc.ModelBinding;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Extensions
{
    public static class ModelStateDictionaryExtensions
    {
        public static List<String> GetErrors(this ModelStateDictionary modelState)
        {
            var errors = new List<String>();
            foreach (var state in modelState.Values)
            {
                foreach (var error in state.Errors)
                {
                    errors.Add(error.ErrorMessage);
                }
            }
            return errors;
        }
    }
}
