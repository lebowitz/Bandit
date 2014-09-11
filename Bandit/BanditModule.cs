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

namespace Bandit
{
    public class BanditModule : IHttpModule
    {
        private const string DEFAULT_TRUSTED_IP_REGEX = @"^10\.10\.0\.|^192\.168\.|^127\.0\.0\.1$|^::1$|^0\.0\.0\.0$";
        private static byte _maxRequestsPerSecond = 8;
        private static TimeSpan _banDuration = TimeSpan.FromMinutes(2);
        private static Dictionary<string, byte> _ipAddresses = new Dictionary<string, byte>();
        private static Dictionary<string,DateTime> _ipBannedUntil = new System.Collections.Generic.Dictionary<string,DateTime>();
        private static Regex _trustedIpRegex = new Regex(DEFAULT_TRUSTED_IP_REGEX, RegexOptions.Compiled);
        private static Amazon.SimpleNotificationService.AmazonSimpleNotificationServiceClient _snsClient;
        private static string _snsTopic;
        private static Timer _cleanupTimer = new Timer { Interval = TimeSpan.FromSeconds(1).TotalMilliseconds, Enabled = true };
        private static bool _isEnabled = true;

        static BanditModule()
        {
            Configure();
            if (_isEnabled)
            {
                _cleanupTimer.Elapsed += _cleanupTimer_Elapsed;
                _cleanupTimer.Start();
            }
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
            if (_isEnabled)
            {
                context.BeginRequest += BeginRequest;
            }
        }

        private void BeginRequest(object sender, EventArgs e)
        {
 	        string ip = HttpContext.Current.Request.UserHostAddress;
            if(_trustedIpRegex.IsMatch(ip))
            {
                if (HttpContext.Current.Request.QueryString != null) {
                    if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["BanditTest"]))
                    {
                        CheckIpAddress(ip);
                    }
                    if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["BanditInfo"]))
                    {
                        WriteInfoToResponse();
                    }
                    if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["BanditClear"]))
                    {
                        Clear();
                    }
                }
            }
            else {
                CheckIpAddress(ip);
            }

            CheckForBan(ip);
        }

        private static void CheckForBan(string ip)
        {
            lock (_ipBannedUntil)
            {
                if (_ipBannedUntil.ContainsKey(ip))
                {
                    if (_ipBannedUntil[ip] > DateTime.Now)
                    {
                        HttpContext.Current.Response.Clear();
                        HttpContext.Current.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                        HttpContext.Current.Response.Write(
                            "Your IP Address, " + ip + ", has been temporarily blocked." +
                            "<br /> Please try again later, or contact your administrator.");
                        HttpContext.Current.Response.Flush();
                        HttpContext.Current.Response.End();
                    }
                    else
                    {
                        _ipBannedUntil.Remove(ip);
                    }
                }
            }
        }

        private static void Clear()
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

        private static void WriteInfoToResponse()
        {
            lock (_ipBannedUntil)
            {
                HttpContext.Current.Response.Write("Blocked Count:" + _ipBannedUntil.Keys.Count() + "<br />");
                foreach (KeyValuePair<string, DateTime> kvp in _ipBannedUntil)
                {
                    HttpContext.Current.Response.Write("Blocked IP:" + kvp.Key + " Until:" + kvp.Value + "<br />");
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
                if (concurrentRequests > _maxRequestsPerSecond)
                {
                    lock (_ipBannedUntil)
                    {
                        if (!_ipBannedUntil.ContainsKey(ip))
                        {
                            _ipBannedUntil[ip] = DateTime.Now + _banDuration;
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
            string banText = string.Format("Banned for {0} seconds.\n\nMachine {1}\nIP: {2}\nUseragent: {3}\nURL: {4}", _banDuration.TotalSeconds, Environment.MachineName, ip, httpRequest.UserAgent, httpRequest.Url);

            Trace.WriteLine(banText);

            if(_snsClient != null) {
                var  req = new PublishRequest();
                req.Message = banText;
                req.TopicArn = _snsTopic;
                Trace.Write(JsonConvert.SerializeObject(req));
                PublishResponse res = _snsClient.Publish(req);
            }
        }

        private static void Configure()
        {
            Trace.WriteLine("Read Configuration");
            string configMaxRequestsPerSecond = System.Configuration.ConfigurationManager.AppSettings.Get("Bandit.MaxRequestsPerSecond");
            byte MaxRequestsPerSecond;
            if (byte.TryParse(configMaxRequestsPerSecond, out MaxRequestsPerSecond))
            {
                _maxRequestsPerSecond = MaxRequestsPerSecond;
            }

            Trace.WriteLine("MaxRequestsPerSecond: " + _maxRequestsPerSecond);

            string configBanDuration = System.Configuration.ConfigurationManager.AppSettings.Get("Bandit.BanDuration");
            TimeSpan banDuration = TimeSpan.MaxValue;
            if (!string.IsNullOrEmpty(configBanDuration) && TimeSpan.TryParse(configBanDuration, out banDuration))
            {
                _banDuration = banDuration;
            }

            Trace.WriteLine("BanDuration: " + _banDuration);

            string configIsEnabled = System.Configuration.ConfigurationManager.AppSettings.Get("Bandit.IsEnabled");
            bool isEnabled;
            if (bool.TryParse(configIsEnabled, out isEnabled))
            {
                _isEnabled = isEnabled;
            }

            Trace.WriteLine("IsEnabled: " + _isEnabled);


            string configTrustedIpRegex = System.Configuration.ConfigurationManager.AppSettings.Get("Bandit.TrustedIpRegex");
            if (!string.IsNullOrEmpty(configTrustedIpRegex))
            {
                Regex trustedIpRegex = null;
                try
                {
                    trustedIpRegex = new Regex(configTrustedIpRegex, RegexOptions.Compiled);
                }
                catch (ArgumentException)
                {
                    Trace.WriteLine(string.Format("Failed to parse AppSetting[Bandit.TrustedIpRegex]: '{0}'", configTrustedIpRegex));
                }
                if (trustedIpRegex != null)
                {
                    _trustedIpRegex = trustedIpRegex;
                }
            }

            Trace.WriteLine("TrustedIpRegex: " + _trustedIpRegex.ToString());

            string awsKey = ConfigurationManager.AppSettings["Bandit.Notifier.AwsAccessKey"];
            string awsSecret = ConfigurationManager.AppSettings["Bandit.Notifier.AwsSecretKey"];
            string awsSnsTopic = ConfigurationManager.AppSettings["Bandit.Notifier.AwsSnsTopic"];
            if (!string.IsNullOrEmpty(awsKey)
                && !string.IsNullOrEmpty(awsSecret)
                && !string.IsNullOrEmpty(awsSnsTopic))
            {
                Trace.WriteLine("AwsSnsTopic: " + awsSnsTopic.ToString());
                var creds = new BasicAWSCredentials(awsKey, awsSecret);
                _snsTopic = awsSnsTopic;
                _snsClient = new Amazon.SimpleNotificationService.AmazonSimpleNotificationServiceClient(creds, new Amazon.SimpleNotificationService.AmazonSimpleNotificationServiceConfig() { RegionEndpoint = Amazon.RegionEndpoint.USEast1, ReadEntireResponse = true, LogResponse = true, ServiceURL = "https://sns.us-east-1.amazonaws.com/" });
            }
        }
    }
}
