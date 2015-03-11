It is recommended that the system that will act as the hardening target be baselined against a commonly-accepted security profile. The most commonly used profile for DoD, IC or systems that wish to attain a similar level of hardening, are the DISA STIGs. As of the writing of this document, two profile-sets are available:
- The one that comes with the 'scap-security-guide' RPM and installs to the host's "/usr/share/xml/scap/ssg/content" directory. In general, this will match up fairly closely to the one found on the DISA STIGS' ["Operating Systems - UNIX/Linux"](http://iase.disa.mil/stigs/Documents/U_RedHat_6_V1R6_STIG.zip) page.
- The one from the [DISA Benchmarks](http://iase.disa.mil/stigs/Documents/U_RedHat_6_V1R6_STIG_SCAP_1-1_Benchmark.zip) page.


If using the former, simply install the `scap-security-guide` RPM. If using the latter, grab and install the DISA benchmark profiles (the following assumes an internet-connected system: adjust your method to meet your deployment environment's capabilities). As root, execute something similar to the following:
~~~
( mkdir -p /opt/STIGs/RHEL6/v1r6 && cd /opt/STIGs/RHEL6/v1r6 && \
wget http://iase.disa.mil/stigs/Documents/U_RedHat_6_V1R6_STIG_SCAP_1-1_Benchmark.zip && \
unzip U_RedHat_6_V1R6_STIG_SCAP_1-1_Benchmark.zip )
~~~
Once the desired SCAP definitions have been installed, it will be necessary to select a testing profile to run. To examine the available profiles, run:
~~~
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel6-xccdf.xml
~~~
Note: if using the DISA Benchmark's files, the path to the XCCDF.xml file will depend on where you installed the Benchmark's files to. Adjust accordingly. Running the above command should produce output similar to the following
~~~
Document type: XCCDF Checklist
Checklist version: 1.1
Status: accepted
Generated: 2014-12-23
Imported: 2014-12-29T09:42:38
Resolved: false
Profiles:
        MAC-1_Classified
        MAC-1_Public
        MAC-1_Sensitive
        MAC-2_Classified
        MAC-2_Public
        MAC-2_Sensitive
        MAC-3_Classified
        MAC-3_Public
        MAC-3_Sensitive
Referenced check files:
        U_RedHat_6_V1R6_STIG_SCAP_1-1_Benchmark-oval.xml
                system: http://oval.mitre.org/XMLSchema/oval-definitions-5
~~~
or
~~~
Document type: XCCDF Checklist
Checklist version: 1.1
Status: draft
Generated: 2014-10-15
Imported: 2014-10-15T08:48:01
Resolved: true
Profiles:
        test
        CS2
        common
        server
        stig-rhel6-server-upstream
        usgcb-rhel6-server
        rht-ccp
        CSCF-RHEL6-MLS
        C2S
Referenced check files:
        ssg-rhel6-oval.xml
                system: http://oval.mitre.org/XMLSchema/oval-definitions-5
~~~
Select a profile according to your deployment environment's needs. To run the test, invoke `oscap` similar to:
~~~
( oscap xccdf eval --profile MAC-1_Classified --report \
/var/tmp/STIGreport-MAC-1_Classified-`date "+%Y%m%d%H%M"`.html --results \
/var/tmp/STIGresults-MAC-1_Classified-`date "+%Y%m%d%H%M"`.xml --cpe \
/opt/STIGs/RHEL6/v1r6/U_RedHat_6_V1R6_STIG_SCAP_1-1_Benchmark-cpe-dictionary.xml \
/opt/STIGs/RHEL6/v1r6/U_RedHat_6_V1R6_STIG_SCAP_1-1_Benchmark-xccdf.xml )
~~~
The above will create time-stamped reports and results files in /var/tmp. Copy the results to a system capable of reading the HTML file.
