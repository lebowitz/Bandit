NGP VAN Banhammer
==============

Banhammer is an ASP.NET module which limits the number of requests per second that can come from a single IP address.  The requests per second and ban interval are configurable.  Notification of bans is provided.

###Installation

Add reference to the nuget package.  At application start, the HTTPModule is automatically registered. 

###Configuration

Set the AppSettings keys `Banhammer.Notifier.AwsAccessKey`, `Banhammer.Notifier.AwsSecretKey`, and `Banhammer.Notifier.AwsSnsTopic`.  Amazon [Simple Notification Service](http://aws.amazon.com/documentation/sns/) (SNS) is used to notify site admins of new bans.  You can subscribe via SMS, email, or other delivery methods supported by SNS.

###Testing

The included sample project DemoApp shows a site which is configured for Banhammer.  DemoAttack is a web load test to test making repeated requests from the same ip.   

###Configuration

The following configuration settings are available:

    <add key="Banhammer.Notifier.AwsAccessKey" value="XXXX" />
    <add key="Banhammer.Notifier.AwsSecretKey" value="YYYY" />
    <add key="Banhammer.Notifier.AwsSnsTopic" value="arn:aws:sns:us-east-1:111111111111:Banhammer" />
    <add key="Banhammer.TrustedIpRegex" value="^10\.10\.0\.|^192\.168\.|^127\.0\.0\.1$|^::1$|^0\.0\.0\.0$" />
    <add key="Banhammer.MaxRequestsPerSecond" value="8" />
    <add key="Banhammer.BanTimeoutInMinutes" value="2" />

The following query string variables are available for testing:

* ```?Banhammer.Test=1``` ignores the default IP filtering.
* ```?Banhammer.Info=1``` show the current counts per IP and bans.
* ```?Banhammer.Clear=1``` clear the bans and IP counts.

### Todo
* Expose REST endpoints for `GET /Banhammer/Info` and `DELETE /Banhammer/Bans`  