# Vuls checker with the coverage of Deep Security

Find out high urgency vulnerability that [Vuls](https://github.com/future-architect/vuls) found with Deep Security.
(This tool is the fork from [Amazon Inspector with DeepSecurity](https://github.com/deep-security/amazon-inspector).)

----

## Description
```vulschecker_ds``` is a CLI tool that compares the vulenarebility report from Vuls with The CVE list Deep Security has.
It can help you to find out high urgency vulnerability.
This tool use [DeepSecurity SDK](https://github.com/deep-security/deep-security-py) and refer to [Amazon Inspector with DeepSecurity](https://github.com/deep-security/amazon-inspector).

##Features
* Output vulnerability that Deep Security can't take measures.
    * To use report by Vuls, we found high urgency vulnerability specific server has.
* Two types of output style are available.
    1. Summary list : Output the number of vulnerability.
    2. CVE list : Output CVE list that Deep Security doesn't take measures.

##Requirement
* Python3 or more
* Accessible Deep Security Manager ("Deep Security As A Service" is also okay.)
* JSON-format report of [Vuls](https://github.com/future-architect/vuls)

----

## Index
- [Usage](#usage)
    - [Compare](#usage-compare)
- [SSL Certificate Validation](#ssl-certificate-validation)

## Usage
The syntax for basic command line usage is available by using the ```--help``` switch.

```bash
$ python vulschecker_ds.py help
usage: python vulschecker_ds.py [COMMAND]
   For more help on a specific command, type "python vulschecker_ds.py [COMMAND] --help"

   Available commands:

   compare
      > Compare the vulenarebility report from Vuls with The CVE list Deep Security has

```

Each script in this set works under a common structure. There are several shared arguments;

```bash
  -h, --help
         - show this help message and exit
  -d [DSM], --dsm [DSM]
         - The address of the Deep Security Manager. Defaults to Deep Security as a Service
  --dsm-port [DSM_PORT]
         - The address of the Deep Security Manager.
           Defaults to an AWS Marketplace/software install (:4119).
           Automatically configured for Deep Security as a Service.
  -u [DSM_USERNAME], --dsm-username [DSM_USERNAME]
         - The Deep Security username to access the IP Lists with.
           Should only have read-only rights to IP lists and API access.
  -p [DSM_PASSWORD], --dsm-password [DSM_PASSWORD]
         - The password for the specified Deep Security username.
           Should only have read-only rights to IP lists and API access.
  -t [DSM_TENANT], --dsm-tenant [DSM_TENANT]
         - The name of the Deep Security tenant/account
  -v [VULS_JSON_REPORT_PATH], --vuls-json-report [VULS_JSON_REPORT_PATH]
         - The full-path to JSON-format report of Vulse.
  --ignore-ssl-validation
         - Ignore SSL certification validation.
           Be careful when you use this as it disables a recommended security check.
           Required for Deep Security Managers using a self-signed SSL certificate.
  --verbose
         - Enabled verbose output for the script. Useful for debugging.
```

These core settings allow you to connect to a Deep Security manager or Deep Security as a Service.

```bash
# to connect to your own Deep Security manager
vulschecker_ds.py [COMMAND] -d 10.1.1.0 -u admin -p USE_RBAC_TO_REDUCE_RISK --ignore-ssl-validation

# to connect to Deep Security as a Service
vulschecker_ds.py [COMMAND] -u admin -p USE_RBAC_TO_REDUCE_RISK -t MY_ACCOUNT
```

Each individual command will also have it's own options that allow you to control the behaviour of the command.

You'll notice in the examples, the password is set to USE_RBAC_TO_REDUCE_RISK. In this context, RBAC stands for role based access control.

Currently Deep Security treats API access just like a user logging in. Therefore it is strongly recommended that you create a new Deep Security user for use with this script. This user should have the bare minimum permissions required to complete the tasks.

<a name="usage-compare" />

### compare

The compare command gets the vulnerability that Vuls found and the list of CVE's that Deep Securty can mitigate.
After that, this tool compares vulnerability with CVE's.
(Deep Security focuses on the mitigate of *remotely exploitable* vulnerability using it's intrusion prevention engine.)

```
# Output result of comparison the vulnerability with Deep Security as a Service
python vulschecker_ds.py compare -u USER -p PASSWORD -t TENANT -v /tmp/vuls/results/current/IP.json

# ...for another Deep Security manager
python vulschecker_ds.py compare -u USER -p PASSWORD -d DSM_HOSTNAME -v /tmp/vuls/results/current/IP.json --ignore-ssl-validation
```

This will generate output along the lines of;

```
***********************************************************************
* Coverage Summary
***********************************************************************
Vulnerability found by Vuls are 95 CVEs.
Deep Security's intrusion prevention rule set currently looks for 5332 CVEs.

89 (93.68%) of the CVEs that Vuls found remain as vulnerability under the coverage of Deep Security.

```

You can also use the ```--print-cve-only``` switch to generate a list of CVEs that remains as vulnerability under the coverage of Deep Security. That generates output along the lines of;

```
CVE-2015-1819
CVE-2015-2328
CVE-2015-3195
CVE-2015-3196
CVE-2015-3223
...
CVE-2016-2150
CVE-2016-3115
CVE-2016-3191
CVE-2016-3698
CVE-2016-3710
```

<a name="ssl-certificate-validation" />

## SSL Certificate Validation

If the Deep Security Manager (DSM) you're connecting to was installed via software of the AWS Marketplace, there's a chance that it is still using the default, self-signed SSL certificate. By default, python checks the certificate for validity which it cannot do with self-signed certificates.

If you are using self-signed certificates, please use the new ```--ignore-ssl-validation``` command line flag.

When you use this flag, you're telling python to ignore any certificate warnings. These warnings should be due to the self-signed certificate but *could* be for other reasons. It is strongly recommended that you have alternative mitigations in place to secure your DSM.

When the flag is set, you'll see this warning block;

```bash
***********************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a less secure method
* of connecting to a Deep Security Manager (DSM). Please ensure that you have other
* mitigations and security controls in place (like restricting IP space that can access
* the DSM, implementing least privilege for the Deep Security user/role accessing the
* API, etc).
*
* During script execution, you'll see a number of "InsecureRequestWarning" messages.
* These are to be expected when operating without validation.
***********************************************************************
```

And during execution you may see lines similar to;

```python
.../requests/packages/urllib3/connectionpool.py:789: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
```

These are expected warnings. Can you tell that we (and the python core teams) are trying to tell you something? If you're interesting in using a valid SSL certificate, you can get one for free from [Let's Encrypt](https://letsencrypt.org), [AWS themselves](https://aws.amazon.com/certificate-manager/) (if your DSM is behind an ELB), or explore commercial options (like the [one from Trend Micro](http://www.trendmicro.com/us/enterprise/cloud-solutions/deep-security/ssl-certificates/)).

----

## References / Related Projects
* [Vuls](https://github.com/future-architect/vuls)
* [DeepSecurity SDK](https://github.com/deep-security/deep-security-py)
* [Amazon Inspector with DeepSecurity](https://github.com/deep-security/amazon-inspector).

----

## Author
[kn0630](https://github.com/kn0630)

## Change log
Please see [CHANGELOG](https://github.com/kn0630/vulschecker_ds/CHANGELOG.md)

## Licence
Please see [LICENSE](https://github.com/kn0630/vulschecker_ds/LICENSE)

