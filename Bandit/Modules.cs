using Microsoft.Web.Infrastructure.DynamicModuleHelper;
using Bandit;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;

[assembly: PreApplicationStartMethod(typeof(StartUp), "PreApplicationStart")]
namespace Bandit
{
    public static class StartUp
    {
        public static void PreApplicationStart()
        {
            Trace.WriteLine("Added Bandit IHttpModule.");
            DynamicModuleUtility.RegisterModule(typeof(BanditModule));
        }
    }
}