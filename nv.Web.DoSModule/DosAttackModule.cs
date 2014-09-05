using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Specialized;
using System.Net;
using System.Diagnostics;

namespace nv.Web.Modules
{
    public class DoSAttackModule : IHttpModule
    {
        private static Dictionary<string, byte> _ipAddresses = new Dictionary<string, byte>();
        private static Dictionary<string,DateTime> _ipBannedUntil = new System.Collections.Generic.Dictionary<string,DateTime>();
        private static DateTime _dateLastCleaned;
        private static bool _isCleanRunning;
        private const short MAX_CONCURRENT_REQUESTS = 40;
        private const int REDUCTION_INTERVAL_IN_SECONDS = 1; // How often cleanup should run
        private const int RELEASE_INTERVAL_IN_MINUTES = 2; // How many minutes to block them for.

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
            if(ip.StartsWith("10.10.0.")
               || ip.StartsWith("192.168.")
               || ip == "127.0.0.1"
               || ip == "::1"
               || ip == "0.0.0.0") 
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
                    if (secondsSinceLastClean > REDUCTION_INTERVAL_IN_SECONDS) {
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

                        // it has been at least REDUCTION_INTERVAL_SECONDS since we last cleaned (makes sure we don't clean too often!) 
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
                if (concurrentRequests > MAX_CONCURRENT_REQUESTS)
                {
                    lock (_ipBannedUntil)
                    {
                        if (!_ipBannedUntil.ContainsKey(ip))
                        {
                            _ipBannedUntil[ip] = DateTime.Now.AddMinutes(RELEASE_INTERVAL_IN_MINUTES);
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
