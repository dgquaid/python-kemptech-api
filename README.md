KEMP API Python SDK
====================
This is a python implementation of a wrapper around the KEMP RESTful API

Installation 
============
To install run:
`pip install python-kemptech-api`

Documentation
=====
For sphinx generated API documentation see [kemptechnologies.github.io/python-kemptech-api](https://kemptechnologies.github.io/python-kemptech-api/) which is based on the `gh-pages` branch. Generated using [Travis](https://travis-ci.org/KEMPtechnologies/python-kemptech-api). Doc sources can be found in [docs](docs). 

##Models 

### BaseKempAppliance

* Contains the basic capabilities available in all LoadMaster products 
    * Patching
    * General parameter control
    * Rebooting
    * Licensing
    * User and password management
    * Logs/Diagnostics
    * Backup/Restore
    * Stats
    * Network Management

### LoadMaster

* Contains L4/L7 ADC Logic
    * Virtual Services
        * SubVSs
    * Real Servers
    * Content Rules
    * Certificates
    * Cipher Suites
    * Templates
    * SSO Management
    * [WAF](https://kemptechnologies.com/solutions/WAF/) Rule Download
    * Adaptive Parameter Control
    * Healthcheck Parameter Control
    * SDN Controller

### GEO

* Contains DNS Load Balancer logic
    * FQDNs
    * Sites
    * Clusters
    * IP Ranges
    * Custom Location
    * IP Blacklist Download
    * DNSSEC Management
    
### LoadMasterGEO

* Meta-subclass of both LoadMaster and GEO and allows control of both sets of functionality within one object.
 
### Objects 

  * VirtualService
  * RealServer
  * BaseACLObject
  * GlobalACL
  * VirtualServiceACL
  * Template
  * Rule
  * Sso
  * Fqdn
  * Site
  * Cluster
  * Range
  * CustomLocation
  * CipherSet
  * Certificate
  * IntermediateCertificate
  * Interface


Examples
=====
To help our end-users with use cases and examples, we've created an [examples](examples) section. If you're in need of assitance and would like an example created, please create an issue explaining your use case and we'll consider it for review.

If you need help getting started check out [this blogpost](https://kemptechnologies.com/blog/getting-started-kemp-python-sdk/) for help.

Tests
=====
To run tests run `nosetests`

Contributions
=============
If you're interested in contributing to this project, please read: 

* If you'd like to contribute but would like help, please open an issue.
* All code contributions require test coverage. If a pull request is lacking tests, it will be closed.
* Docstrings are welcomed. We auto-gen docs into the `gh-pages` branch using [Travis](https://travis-ci.org/KEMPtechnologies/python-kemptech-api). 
* If you're submitting a feature, please clearly explain its use case in your pull request. Our team gets warm and fuzzies every time a contribution is made and explanations help greatly.

Bugs
=====
If you believe you've found a bug please create an issue. We may not get to it right away, but rest assured we've seen it and have it queued up for a response. Seriously, we're watching.

Changelog
=========
For changelog see [changes.rst](CHANGES.rst)

Core Contributors
============

* Shane McGough, KEMP Technologies
* Andrew Conti, KEMP Technologies
* Jonathan Malek, KEMP Technologies
* Stephen Power, KEMP Technologies

License
=====
This library is __licensed__ under the Apache 2.0 License. The terms of the license are as follows: 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
