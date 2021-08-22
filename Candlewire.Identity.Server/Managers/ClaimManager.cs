using Candlewire.Identity.Server.Entities;
using Candlewire.Identity.Server.Extensions;
using Candlewire.Identity.Server.Settings;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Managers
{
    public class ClaimManager
    {
        public List<Claim> ExtractClaims(AuthenticateResult result)
        {
            var principal = result.Principal;
            var claims = principal.Claims.ToList();
            var basics = new List<Claim>();

            var fullName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            var firstName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
            var lastName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
            var emailAddress = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            var phoneNumber = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.PhoneNumber)?.Value ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.MobilePhone)?.Value;
            var nickName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.NickName)?.Value;
            var upnValue = claims.FirstOrDefault(a => a.Type == ClaimTypes.Upn)?.Value;

            if (fullName?.Contains("\\") == false && fullName?.Contains("@") == false && fullName?.Contains(" ") == true)
            {
                var array = fullName?.Split(" ");
                
                if (firstName == null) {
                    if (array[0]?.Trim() != "")
                    {
                        firstName = array[0];
                    }
                }

                if (lastName == null)
                {
                    var position = array.Length - 1;
                    if (array[position]?.Trim() != "")
                    {
                        lastName = array[position];
                    }
                }
            }

            if (emailAddress == null && upnValue != null)
            {
                if (upnValue.IsValidEmail() == true)
                {
                    emailAddress = upnValue;
                }
            }

            if (fullName != null) { basics.Add(new Claim(JwtClaimTypes.Name, fullName)); }
            if (firstName != null) { basics.Add(new Claim(JwtClaimTypes.GivenName, firstName)); }
            if (lastName != null) { basics.Add(new Claim(JwtClaimTypes.FamilyName, lastName)); }
            if (emailAddress != null) { basics.Add(new Claim(JwtClaimTypes.Email, emailAddress.Replace(";", "").Trim())); }
            if (phoneNumber != null) { basics.Add(new Claim(JwtClaimTypes.PhoneNumber, phoneNumber)); }
            if (nickName != null) { basics.Add(new Claim(JwtClaimTypes.NickName, nickName)); }
            /* Need to look into extracting address information as well */

            return basics;
        }

        public List<String> ExtractRoles(AuthenticateResult result)
        {
            var principal = result.Principal;
            var claims = principal.Claims.ToList();
            var roleClaims = claims.Where(a => a.Type == JwtClaimTypes.Role)?.ToList() ?? claims.Where(a => a.Type == ClaimTypes.Role)?.ToList();
            return roleClaims.Select(a => a.Value).ToList();
        }

        public List<Claim> BuildClaims(String userName, String emailAddress, String phoneNumber, String firstName, String lastName, String nickName, DateTime? birthDate, String shippingAddress, String billingAddress, String terms = null)
        {
            var claims = new List<Claim>();

            if (!String.IsNullOrEmpty(emailAddress)) { claims.Add(new Claim(JwtClaimTypes.Email, emailAddress.Trim().Replace(";", ""))); };
            if (!String.IsNullOrEmpty(phoneNumber)) { claims.Add(new Claim(JwtClaimTypes.PhoneNumber, phoneNumber.Trim())); };
            if (!String.IsNullOrEmpty(nickName)) { claims.Add(new Claim(JwtClaimTypes.Name, firstName.Trim() + " " + lastName.Trim())); }
            if (!String.IsNullOrEmpty(firstName)) { claims.Add(new Claim(JwtClaimTypes.GivenName, firstName.Trim())); }
            if (!String.IsNullOrEmpty(lastName)) { claims.Add(new Claim(JwtClaimTypes.FamilyName, lastName.Trim())); }
            if (!String.IsNullOrEmpty(userName)) { claims.Add(new Claim(JwtClaimTypes.PreferredUserName, userName)); }
            if (!String.IsNullOrEmpty(nickName)) { claims.Add(new Claim(JwtClaimTypes.NickName, nickName.Trim())); }
            if (!String.IsNullOrEmpty(terms)) { claims.Add(new Claim("terms", terms.Trim())); }
            if (!String.IsNullOrEmpty(shippingAddress)) { claims.Add(new Claim("shipping_address", shippingAddress.Trim())); }
            if (!String.IsNullOrEmpty(billingAddress)) { claims.Add(new Claim("billing_address", billingAddress.Trim())); }
            if (birthDate != null) { claims.Add(new Claim(JwtClaimTypes.BirthDate, Convert.ToDateTime(birthDate).ToString("M/d/yyyy"))); }
            if (!String.IsNullOrEmpty(firstName) && !String.IsNullOrEmpty(lastName)) { claims.Add(new Claim(JwtClaimTypes.Name, firstName.Trim() + " " + lastName.Trim())); }
            
            return claims;
        }
    }
}
