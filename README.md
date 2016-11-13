# SMTP-STS Validator

[![GoDoc](https://godoc.org/github.com/danmarg/smtp-sts?status.svg)](https://godoc.org/github.com/danmarg/smtp-sts)

This is a simple library and command line tool implementing a primitive
[SMTP-STS](https://datatracker.ietf.org/doc/draft-ietf-uta-mta-sts/)
validator.

The library has four commands:
~~~
     getdns     fetch the domain's policy *version* and print it
     getpolicy  fetch the domain's policy and print it
     getmxs     fetch the domain's policy and MXs, and filter the MXs against the policy, reporting any which are invalid
     testsmtp   fetch the domain's policy and MXs, filter the MXs, and test STARTTLS
~~~

Example usage:
~~~
$ ./bin/cli getdns yahoo.com                                                                                  
Version: 20161109010200Z
$ ./bin/cli getpolicy yahoo.com                                                                               
Policy: {1 [*.am0.yahoodns.net] 2016-11-14 11:16:30.414524442 +0000 UTC }
$ ./bin/cli getmxs yahoo.com                                                                                  
Policy: {1 [*.am0.yahoodns.net] 2016-11-14 11:16:51.858961329 +0000 UTC }
Matching MXes: 
        mta7.am0.yahoodns.net.  1
        mta5.am0.yahoodns.net.  1
        mta6.am0.yahoodns.net.  1
$ ./bin/cli testsmtp yahoo.com                                                                                
Policy: {1 [*.am0.yahoodns.net] 2016-11-14 11:17:05.269545742 +0000 UTC }
Matching MXes: 
        mta7.am0.yahoodns.net.  1
        mta5.am0.yahoodns.net.  1
        mta6.am0.yahoodns.net.  1
Testing MX mta7.am0.yahoodns.net....OK!
Testing MX mta5.am0.yahoodns.net....OK!
Testing MX mta6.am0.yahoodns.net....OK!
~~~
