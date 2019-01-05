certdiff
========

This tool allows you to compare the properties of a
given certificate against the prescribed properties
from the configuration file and report on any
differences.

Please see the
[man page](doc/certdiff.txt)
for details.

If you have questions, comments, or suggestions,
please contact the author at
[jschauma@netmeister.org](mailto:jschauma@netmeister.org)
or at [@jschauma](https://twitter.com/jschauma).

## Examples

### Example Configuration File

The following example configuration file mandates that

* all certificates have Certificate Transparency logs
* valid domains for Subject and SANs must end in 'example.com' or 'example.net'
* ECDSA certificates must use a key length of at least 386 bits
* RSA certificates must use a key length of at least 2048 bits
* certificates must not be valid for more than 180 days
* certificates must not have more than 20 SANs
* of the SANs and the Subject, there may be at most 4 wildcard names
* certificates must be signed using SHA256-RSA
* certificates must chain to either the DigiCert EV Root (by way of sha1 pin), or to the VeriSign G5 root (by way of the root serial number)

certdiff(1) will use the the default trusted CA bundle
from /etc/pki/tls/cert.pem, since 'cabundle' is not
specified in the configuration file.

```
ct = true 
domains = example.com, example.net
keyLengthECDSA = 386
keyLengthRSA = 2048
maxValidity = 180
maxSANs = 20
maxWildcards = 4

# We only accept certificates issued by the
# DigiCert High Assurance EV Root CA, identified by
# this sha1 pin:
# curl https://www.digicert.com/CACerts/DigiCertHighAssuranceEVRootCA.crt | \
#     openssl x509 -inform DER -pubkey -noout                             | \
#     openssl rsa -pubin -outform DER 2>/dev/null                         | \
#     openssl dgst -sha1 -binary                                          | \
#     openssl enc -base64
pins = sha1/gzF+YoVCU9bXeDGQ7JGQVumRueM=

# Oh, wait, we changed our mind, we also accept
# VeriSign Class 3 Public Primary CA - G5
rootSerials = 18DAD19E267DE8BB4A2158CDCC6B3B4A

sigAlgs = SHA256-RSA
```

### Checking a local certificate

A single stand-alone certificate will likely fail some
of the checks, since the certificate cannot be
validated without intermediates:

```
$ certdiff -c /tmp/certdiffrc < cert.pem
80205c2c70ab32906cea79d6b6e790f8 'foo.bar.example.com' (leaf): Incomplete chain!
80205c2c70ab32906cea79d6b6e790f8 'foo.bar.example.com' (leaf): validity > maxValidity (730 > 180)
80205c2c70ab32906cea79d6b6e790f8 'foo.bar.example.com' (leaf): no longer valid
80205c2c70ab32906cea79d6b6e790f8 'foo.bar.example.com' (leaf): Unable to verify validity: x509: certificate signed by unknown authority
80205c2c70ab32906cea79d6b6e790f8 'foo.bar.example.com' (leaf): no valid pin nor root serial found.
$ 
```

In addition, this certificate has a validity longer
than what we require and has already expired.

### Checking a remote service

You can also use certdiff(1) to check the certificate
chain provided by a remote service directly:

```
$ certdiff -s www.yahoo.com
1c25430ed0a602e8cc3a977b0539cce5 'www.yahoo.com' (leaf): too many wildcards (13 > 4).
1c25430ed0a602e8cc3a977b0539cce5 'www.yahoo.com' (leaf): validity > maxValidity (730 > 180)
1c25430ed0a602e8cc3a977b0539cce5 'www.yahoo.com' (leaf): too many SANs (65 > 20)
$ 
```

### Listing certificate properties

certdiff(1) also allows you to just report certificate
properties.  That is very similar to running

```
openssl x509 -text -noout
```

but adds certificate pins, the full chain, and some
other details:

```
$ certdiff -l -s www.symantec.com

Leaf cert 'www.symantec.com' from input:
  signed by 'Symantec Class 3 EV SSL CA - G3' (7ee14a6f6feff2d37f3fad654d3adab4; sha1/R0nfFlf0bIvSjHkbmfufKIEqYOA=; sha256/gMxWOrX4PMQesK9qFNbYBxjBfjUvlkn/vN1n+L9lE5E=)
    signed by 'VeriSign Class 3 Public Primary Certification Authority - G5' (18dad19e267de8bb4a2158cdcc6b3b4a; sha1/sYEIGhmkwJQf+uiVKMEkyZs0rMc=; sha256/JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg=)

CN         : www.symantec.com
Serial     : 29ea653a26485e380c86b360f00cc1c8
Validity   : 235
Verified   : valid
SANs       : bcportal.symantec.com, go.symantec.com, m.symantec.com, my-qa.symantec.com, my-uat.symantec.com, my.symantec.com, partnernet-internal.norton.com, partnernet-internal.symantec.com, partnernet-qa.norton.com, partnernet-qa.symantec.com, partnernet-sit.symantec.com, partnernet-temp.symantec.com, partnernet-uat.norton.com, partnernet-uat.symantec.com, partnernet.norton.com, partnernet.symantec.com, scm.symantec.com, securityresponse.symantec.com, sites-internal.symantec.com, sites-qa.symantec.com, sites-uat.symantec.com, sites.symantec.com, www.go.symantec.com, www.symantec.com, www4.symantec.com
KeyLength  : 2048
Pins       : sha1/1MpIPCkazFdpL6gwT2F2d454B5U=, sha256/JteRGVGWgHPhyIy4rwlk2ZGo+auH/9oWGK2pUKNgZsc=
SigAlgo    : SHA256-RSA
CT log     : https://crt.sh/?id=55061361

```
