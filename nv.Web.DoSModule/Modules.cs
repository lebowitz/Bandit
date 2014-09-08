using Microsoft.Web.Infrastructure.DynamicModuleHelper;
using nv.Web.Modules;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Web;

[assembly: PreApplicationStartMethod(typeof(StartUp), "PreApplicationStart")]
namespace nv.Web.Modules
{
    public static class StartUp
    {
        public static void PreApplicationStart()
        {
            Trace.WriteLine("Added NGP VAN Banhammer IHttpModule.");
            DynamicModuleUtility.RegisterModule(typeof(BanhammerModule));
        }
    }
}