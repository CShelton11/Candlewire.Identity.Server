using Candlewire.Identity.Server.Interfaces;
using Candlewire.Identity.Server.Settings;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace Candlewire.Identity.Server.Senders
{
    public class MessageSender : IEmailSender, ISmsSender
    {
        private SmsSettings SmsSettings;
        private EmailSettings EmailSettings;

        public MessageSender(IOptions<SmsSettings> smsSettings, IOptions<EmailSettings> emailSettings)
        {
            SmsSettings = smsSettings.Value;
            EmailSettings = emailSettings.Value;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var token = EmailSettings.Token;
            var from = EmailSettings.From;
            var provider = EmailSettings.Provider;

            if (provider.ToLower() == "twilio")
            {
                var client = new SendGridClient(token);
                var sender = new EmailAddress(from, from);
                var receiver = new EmailAddress(email, email);
                var item = MailHelper.CreateSingleEmail(sender, receiver, subject, "", message);
                var response = await client.SendEmailAsync(item);
            }
        }

        public async Task SendSmsAsync(string number, string message)
        {
            var provider = SmsSettings.Provider;
            var sid = SmsSettings.Sid;
            var token = SmsSettings.Token;
            var from = SmsSettings.From;

            if (provider.ToLower() == "twilio")
            {
                TwilioClient.Init(sid, token);
                await MessageResource.CreateAsync(
                    body: message,
                    from: new Twilio.Types.PhoneNumber(from),
                    to: new Twilio.Types.PhoneNumber(number)
                );
            }
        }
    }
}
