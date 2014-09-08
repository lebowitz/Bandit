using System;
using System.Web;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Specialized;
using System.Net;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Amazon.Runtime;
using Amazon.SimpleNotificationService.Model;
using Newtonsoft.Json;
using System.Timers;

namespace Banhammer
{
    public class BanhammerModule : IHttpModule
    {
        private const string DEFAULT_TRUSTED_IP_REGEX = @"^10\.10\.0\.|^192\.168\.|^127\.0\.0\.1$|^::1$|^0\.0\.0\.0$";
        private static Dictionary<string, byte> _ipAddresses = new Dictionary<string, byte>();
        private static Dictionary<string,DateTime> _ipBannedUntil = new System.Collections.Generic.Dictionary<string,DateTime>();
        private static byte _MaxRequestsPerSecond = 8;
        private static int _banTimeoutInMinutes = 2;
        private static Regex _trustedIpRegex = new Regex(DEFAULT_TRUSTED_IP_REGEX, RegexOptions.Compiled);
        private static Amazon.SimpleNotificationService.AmazonSimpleNotificationServiceClient _snsClient;
        private static string _snsTopic;
        private static Timer _cleanupTimer = new Timer();

        static BanhammerModule()
        {
            _cleanupTimer.Interval = TimeSpan.FromSeconds(1).TotalMilliseconds;
            _cleanupTimer.Enabled = true;
            _cleanupTimer.Elapsed += _cleanupTimer_Elapsed;
            _cleanupTimer.Start();
            Configure();
        }

        static void _cleanupTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            lock (_ipAddresses)
            {
                _ipAddresses.Clear();
            }
        }

        public void Dispose()
        {}

        public void Init(HttpApplication context)
        {
 	        context.BeginRequest += BeginRequest;
        }

        private void BeginRequest(object sender, EventArgs e)
        {
 	        string ip = HttpContext.Current.Request.UserHostAddress;
            if(_trustedIpRegex.IsMatch(ip))
            {
                if (HttpContext.Current.Request.QueryString != null) {
                    if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["Banhammer.Test"]))
                    {
                        // Allow admins to force this to run even if they're on local IPs for testing
                        CheckIpAddress(ip);
                    }
                    if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["Banhammer.Info"]))
                    {
                        lock (_ipBannedUntil)
                        {
                            HttpContext.Current.Response.Write("Blocked Count:" + _ipBannedUntil.Keys.Count() + "<BR />");
                            foreach (KeyValuePair<string, DateTime> kvp in _ipBannedUntil)
                            {
                                HttpContext.Current.Response.Write("Blocked IP:" + kvp.Key + " Until:" + kvp.Value + "<BR />");
                            }
                        }
                        lock (_ipAddresses)
                        {
                            HttpContext.Current.Response.Write("Tracked Count:" + _ipAddresses.Keys.Count() + "<BR />");
                            foreach (KeyValuePair<string, byte> kvp in _ipAddresses)
                            {
                                HttpContext.Current.Response.Write("Tracked IP:" + kvp.Key + " OpenHits:" + kvp.Value + "<BR />");
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["Banhammer.Clear"]))
                    {
                        lock (_ipBannedUntil)
                        {
                            _ipBannedUntil.Clear();
                        }
                        lock (_ipAddresses)
                        {
                            _ipAddresses.Clear();
                        }
                    }
                }
            }
            else {
                CheckIpAddress(ip);
                //CleanupData();
            }

            lock(_ipBannedUntil)
            {
                if(_ipBannedUntil.ContainsKey(ip))
                {
                    // Figure out if they are past the time.
                    if(_ipBannedUntil[ip] > DateTime.Now)
                    {
                        HttpContext.Current.Response.Clear();
                        HttpContext.Current.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                        HttpContext.Current.Response.Write(
                            "Your IP Address " + ip + " has been temporarily blocked due to suspicious activity."+
                            "<BR> Please try again later or contact your administrator.");
                        HttpContext.Current.Response.Flush();
                        HttpContext.Current.Response.End();
                    }
                    else {
                        // They can come back now.
                        _ipBannedUntil.Remove(ip);
                    }
                }
            }
        }

        /// <summary>
        /// Checks the requesting IP address in the collection and bans the IP, if required.
        /// </summary>
        private void CheckIpAddress(string ip)
        {
            lock (_ipAddresses)
            {
                if (!_ipAddresses.ContainsKey(ip))
                {
                    _ipAddresses[ip] = 1;
                    return;
                }

                short concurrentRequests = _ipAddresses[ip];
                if (concurrentRequests > _MaxRequestsPerSecond)
                {
                    lock (_ipBannedUntil)
                    {
                        if (!_ipBannedUntil.ContainsKey(ip))
                        {
                            _ipBannedUntil[ip] = DateTime.Now.AddMinutes(_banTimeoutInMinutes);
                            _ipAddresses.Remove(ip);
                            NotifyBan(ip, HttpContext.Current.Request);
                        }
                    }
                }
                else
                {
                    byte newConcurrentRequests = (byte) (concurrentRequests + 1);
                    _ipAddresses[ip] = newConcurrentRequests;
                    Trace.WriteLine(string.Format("IP {0} at {1} concurrent requests.", ip, newConcurrentRequests));
                }
            }
        }

        private void NotifyBan(string ip, HttpRequest httpRequest)
        {
            string simpleBanInfo = string.Format("Banned for {0} minutes.\n\nMachine {1}\nIP: {2}\nUseragent: {3}\nURL: {4}", _banTimeoutInMinutes, Environment.MachineName, ip, httpRequest.UserAgent, httpRequest.Url);

            Trace.WriteLine(simpleBanInfo);

            if(_snsClient != null) {
                var  req = new PublishRequest();
                req.Message = simpleBanInfo;
                req.TopicArn = _snsTopic;
                PublishResponse res = _snsClient.Publish(req);
                Trace.WriteLine("Published notification got HTTP " + res.HttpStatusCode.ToString());
            }
        }

        private static void Configure()
        {
            string configMaxRequestsPerSecond = System.Configuration.ConfigurationManager.AppSettings.Get("Banhammer.MaxRequestsPerSecond");
            byte MaxRequestsPerSecond;
            if (byte.TryParse(configMaxRequestsPerSecond, out MaxRequestsPerSecond))
            {
                _MaxRequestsPerSecond = MaxRequestsPerSecond;
            }

            string configBanTimeoutInMinutes = System.Configuration.ConfigurationManager.AppSettings.Get("Banhammer.BanTimeoutInMinutes");
            byte banTimeoutInMinutes;
            if (byte.TryParse(configBanTimeoutInMinutes, out banTimeoutInMinutes))
            {
                _banTimeoutInMinutes = banTimeoutInMinutes;
            }

            string configTrustedIpRegex = System.Configuration.ConfigurationManager.AppSettings.Get("Banhammer.TrustedIpRegex");
            if (!string.IsNullOrEmpty(configTrustedIpRegex))
            {
                Regex trustedIpRegex = null;
                try
                {
                    trustedIpRegex = new Regex(configTrustedIpRegex, RegexOptions.Compiled);
                }
                catch (ArgumentException)
                {
                    Trace.WriteLine(string.Format("Failed to parse AppSetting[Banhammer.TrustedIpRegex]: '{0}'", configTrustedIpRegex));
                }
                if (trustedIpRegex != null)
                {
                    _trustedIpRegex = trustedIpRegex;
                }
            }

            string awsKey = ConfigurationManager.AppSettings["Banhammer.Notifier.AwsAccessKey"];
            string awsSecret = ConfigurationManager.AppSettings["Banhammer.Notifier.AwsSecretKey"];
            string awsSnsTopic = ConfigurationManager.AppSettings["Banhammer.Notifier.AwsSnsTopic"];
            if (!string.IsNullOrEmpty(awsKey)
                && !string.IsNullOrEmpty(awsSecret)
                && !string.IsNullOrEmpty(awsSnsTopic))
            {
                var creds = new BasicAWSCredentials(awsKey, awsSecret);
                _snsTopic = awsSnsTopic;
                _snsClient = new Amazon.SimpleNotificationService.AmazonSimpleNotificationServiceClient(creds, new Amazon.SimpleNotificationService.AmazonSimpleNotificationServiceConfig() { RegionEndpoint = Amazon.RegionEndpoint.USEast1, ReadEntireResponse = true, LogResponse = true, ServiceURL = "https://sns.us-east-1.amazonaws.com/" });
            }
        }
    }
}
