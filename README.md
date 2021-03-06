Bandit is an ASP.NET HttpModule.  It limits the number of requests per second that can come from a single IP address.  The requests per second and ban interval are configurable.  Bans are published to an SNS topic.

[![Build status](https://ci.appveyor.com/api/projects/status/k4idpocpwmiol1nn/branch/master)](https://ci.appveyor.com/project/lebowitz/bandit/branch/master)

###Installation

Add reference to the nuget package.  There is nothing more you need to do.  At application start, the HTTPModule is automatically registered, thanks to WebActivator.  You will be using configuration defaults.

###Configuration

Set the AppSettings keys `Bandit.Notifier.AwsAccessKey`, `Bandit.Notifier.AwsSecretKey`, and `Bandit.Notifier.AwsSnsTopic`.  Amazon [Simple Notification Service](http://aws.amazon.com/documentation/sns/) (SNS) is used to notify site admins of new bans.  You can subscribe via SMS, email, or other delivery methods supported by SNS.

###Testing

The included sample project DemoApp shows a site which is configured for Bandit.  `DemoAttack/Attack.loadtest` helps make repeated requests from the same IP.  Requests count toward then ban: (1) when the either don't match TrustedIpRegex, or (2) have the `Bandit.Test` querystring variable set.

###Configuration

The following configuration settings are available:

    <add key="Bandit.Notifier.AwsAccessKey" value="XXXX" />
    <add key="Bandit.Notifier.AwsSecretKey" value="YYYY" />
    <add key="Bandit.Notifier.AwsSnsTopic" value="arn:aws:sns:us-east-1:111111111111:Bandit" />
    <add key="Bandit.TrustedIpRegex" value="^10\.10\.0\.|^192\.168\.|^127\.0\.0\.1$|^::1$|^0\.0\.0\.0$" />
    <add key="Bandit.MaxRequestsPerSecond" value="8" />
    <add key="Bandit.BanTimeoutInMinutes" value="2" />

The following query string variables are available for testing:

* ```?Bandit.Test=1``` ignores the default IP filtering.
* ```?Bandit.Info=1``` show the current counts per IP and bans.
* ```?Bandit.Clear=1``` clear the bans and IP counts.

### Todo

* Implement incremental delays instead of killing the page (optionally): http://jasonwatmore.com/post/2015/06/03/CSharp-Incremental-Delay-to-Prevent-Brute-Force-or-Dictionary-Attack.aspx

* Add support for longer check intervals than one second (currently hardcoded). For example, to stop  bots that constantly, but slowly tries brute force or sql injection attacks over a number of hours or days.

* Hammer graphic
* Expose REST endpoints for `GET /Bandit/Info` and `DELETE /Bandit/Bans`
