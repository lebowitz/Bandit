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

namespace nv.Web.Modules
{
    public class DoSAttackModule : IHttpModule
    {
        private const string DEFAULT_TRUSTED_IP_REGEX = @"^10\.10\.0\.|^192\.168\.|^127\.0\.0\.1$|^::1$|^0\.0\.0\.0$";
        private static Dictionary<string, byte> _ipAddresses = new Dictionary<string, byte>();
        private static Dictionary<string,DateTime> _ipBannedUntil = new System.Collections.Generic.Dictionary<string,DateTime>();
        private static DateTime _dateLastCleaned;
        private static bool _isCleanRunning;
        private static byte _maxConcurrentRequests = 32;
        private static int _cleanupFrequencyInSeconds = 1;
        private static int _banTimeoutInMinutes = 2;
        private static Regex _trustedIpRegex;

        static DoSAttackModule()
        {
            Configure();
        }

        private static void Configure()
        {
            string configMaxConcurrentRequests = System.Configuration.ConfigurationManager.AppSettings.Get("DoSAttackModule.MaxConcurrentRequests");
            byte maxConcurrentRequests;
            if (byte.TryParse(configMaxConcurrentRequests, out maxConcurrentRequests))
            {
                _maxConcurrentRequests = maxConcurrentRequests;
            }

            string configCleanupFrequencyInSeconds = System.Configuration.ConfigurationManager.AppSettings.Get("DoSAttackModule.CleanupFrequencyInSeconds");
            byte cleanupFrequencyInSeconds;
            if (byte.TryParse(configCleanupFrequencyInSeconds, out cleanupFrequencyInSeconds))
            {
                _cleanupFrequencyInSeconds = cleanupFrequencyInSeconds;
            }

            string configBanTimeoutInMinutes = System.Configuration.ConfigurationManager.AppSettings.Get("DoSAttackModule.BanTimeoutInMinutes");
            byte banTimeoutInMinutes;
            if (byte.TryParse(configBanTimeoutInMinutes, out banTimeoutInMinutes))
            {
                _banTimeoutInMinutes = banTimeoutInMinutes;
            }

            string configTrustedIpRegex = System.Configuration.ConfigurationManager.AppSettings.Get("DoSAttackModule.TrustedIpRegex");
            if (!string.IsNullOrEmpty(configTrustedIpRegex))
            {
                Regex trustedIpRegex = null;
                try
                {
                    trustedIpRegex = new Regex(configTrustedIpRegex, RegexOptions.Compiled);
                }
                catch(ArgumentException)
                {
                    Trace.WriteLine(string.Format("Failed to parse AppSetting[DoSAttackModule.TrustedIpRegex]: '{0}'", configTrustedIpRegex));
                }
                if(trustedIpRegex != null)
                {
                    _trustedIpRegex = trustedIpRegex;
                }
                else
                {
                    _trustedIpRegex = new Regex(DEFAULT_TRUSTED_IP_REGEX, RegexOptions.Compiled);
                }
            }
        }

        public void Dispose()
        {}

        public void Init(HttpApplication context)
        {
 	        context.BeginRequest += BeginRequest;
            context.EndRequest += EndRequest;
        }

        private void BeginRequest(object sender, EventArgs e)
        {
 	        string ip = HttpContext.Current.Request.UserHostAddress;
            if(_trustedIpRegex.IsMatch(ip))
            {
                if (HttpContext.Current.Request.QueryString != null) {
                    if(!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["DOSTest"]))
                    {
                        // Allow admins to force this to run even if they're on local IPs for testing
                        CheckIpAddress(ip);
                        CleanupData();
                    }
                    if(!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["ShowDOSInfo"]))
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
                    if(!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString["ClearDOSInfo"]))
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
                CleanupData();
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
                        HttpContext.Current.Response.Write("Your IP Address " + ip + " has been temporarily blocked due to suspicious activity.<BR> Please try again later or contact your administrator.");
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

        private void CleanupData()
        {
            if (_isCleanRunning) {
                _isCleanRunning = true;
                try {
                    long secondsSinceLastClean = (long)(DateTime.Now - _dateLastCleaned).TotalSeconds;
                    if (secondsSinceLastClean > _cleanupFrequencyInSeconds) {
                        byte reduction;
                        if (secondsSinceLastClean > 60)
                        {
                            reduction = 1;
                        }
                        else
                        {
                            reduction = (byte)secondsSinceLastClean;
                        }

                        secondsSinceLastClean = secondsSinceLastClean + 1;

                        // it has been at least _cleanupFrequencyInSeconds since we last cleaned (makes sure we don't clean too often!) 
                        // sets the time interval for basis of number of open connections.
                        // First reduce counts on ip table.
                        List<string> ips = _ipAddresses.Keys.ToList();
                        foreach (var ip in ips)
                        {
                            byte concurrentRequests = _ipAddresses[ip];
                            if (concurrentRequests <= reduction)
                            {
                                _ipAddresses.Remove(ip);
                            }
                            else
                            {
                                _ipAddresses[ip] = (byte)(concurrentRequests - reduction);
                            }
                        }
                    }
                    _dateLastCleaned = DateTime.Now;
                }
                catch(Exception) {}
                _isCleanRunning = false;
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
                if (concurrentRequests > _maxConcurrentRequests)
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
                    _ipAddresses[ip] = (byte) (concurrentRequests + 1);
                }
            }
        }

        private void NotifyBan(string ip, HttpRequest httpRequest)
        {
            Trace.WriteLine("ban " + ip);
        }

        void EndRequest(object sender, EventArgs e)
        {
 	        // If the request ends, let's remove a call from this user (the count will now be how many incomplete requests they have)
            string ip = HttpContext.Current.Request.UserHostAddress;
            lock(_ipAddresses)
            {
                if(_ipAddresses.ContainsKey(ip)) {
                    short myInt = _ipAddresses[ip];
                    if(myInt - 1 <= 0)
                    {
                        _ipAddresses.Remove(ip);
                    }
                    else
                    {
                        _ipAddresses[ip] = (byte)(myInt - 1);
                    }
                }
            }
        }
    }
}
