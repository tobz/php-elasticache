php-elasticacache
=================

A PHP extension for pulling down ElastiCache configuration information, automatically, at runtime.

why
=================

Because Amazon has still yet to release the source code to their version of the Memcached plugin and I'm not a fan of using things that I can't look at the source code for.

how it works
=================

This extension provides two features: automatic auto-discovery pulldown and session path updating.  It is designed to interoperate seamlessly with the [PECL Memcached extension](http://pecl.php.net/package/memcached).

automatic auto-discovery pulldown
-----------------

Automatic auto-discovery pulldown is a fancy way of saying that you specify ElastiCache configuration endpoint(s), and every request, the extension will query those endpoint(s), grab the list of nodes per configuration endpoint, and make them available in the _SERVER superglobal.

You can specify the list of configuration endpoints as such: *name://host:port[,name://host:port ...]*

The 'name' portion represents the name of the endpoint.  You must give each endpoint a unique name.  'host' and 'port' represent the configuration endpoint FQDN and the port, respectively.  An example would be:

*elasticache.endpoints = "web://web.xyz.cache.amazonaws.com:11211"*

If you want to pull down multiple endpoints, it's simply:

*elasticache.endpoints = "web://web.xyz.cache.amazonaws.com:11211,service://service.xyz.cache.amazonaws.com:11211"*

The structure created by the extension is suitable for passing directly to [Memcached::addServers](http://www.php.net/manual/en/memcached.addservers.php).

session path updating
-----------------

If you're using ElastiCache, there's a good chance that maybe you're also using it for PHP sessions.  If so, there is a special notation you can use when defining the list of ElastiCache nodes to indicate that the resulting endpoint represents your session cache.  Just send the name of the endpoint to *session*.  When the extension sees this, it will automatically update *session.save_path* in the format expected by the Memcached extension to allow your session pool to be automatically configured, dynamically, with no adjusting of configuration files.
