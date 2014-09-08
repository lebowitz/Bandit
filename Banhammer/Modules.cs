using Microsoft.Web.Infrastructure.DynamicModuleHelper;
using Banhammer;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Web;

[assembly: PreApplicationStartMethod(typeof(StartUp), "PreApplicationStart")]
namespace Banhammer
{
    public static class StartUp
    {
        public static void PreApplicationStart()
        {
            Trace.WriteLine("Added Banhammer IHttpModule.");
            DynamicModuleUtility.RegisterModule(typeof(BanhammerModule));
        }
    }
}