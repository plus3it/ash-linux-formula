# Rule ID:              content_rule_rsyslog_remote_loghost
# Finding Level:        medium
#
# Rule Summary:
#       The rsyslog service must be configured to send logs to a remote log
#       server
#
# References:
#   - ANSSI
#     - BP28(R7)
#     - NT28(R43)
#     - NT12(R5)
#   - CIS-CSC
#     - 1
#     - 13
#     - 14
#     - 15
#     - 16
#     - 2
#     - 3
#     - 5
#     - 6
#   - COBIT5
#     - APO11.04
#     - APO13.01
#     - BAI03.05
#     - BAI04.04
#     - DSS05.04
#     - DSS05.07
#     - MEA02.01
#   - DISA
#     - CCI-000366
#     - CCI-001348
#     - CCI-000136
#     - CCI-001851
#   - HIPAA
#     - 164.308(a)(1)(ii)(D)
#     - 164.308(a)(5)(ii)(B)
#     - 164.308(a)(5)(ii)(C)
#     - 164.308(a)(6)(ii)
#     - 164.308(a)(8)
#     - 164.310(d)(2)(iii)
#     - 164.312(b)
#     - 164.314(a)(2)(i)(C)
#     - 164.314(a)(2)(iii)
#   - ISA-62443-2009
#     - 4.3.3.3.9
#     - 4.3.3.5.8
#     - 4.3.4.4.7
#     - 4.4.2.1
#     - 4.4.2.2
#     - 4.4.2.4
#   - ISA-62443-2013
#     - SR 2.10
#     - SR 2.11
#     - SR 2.12
#     - SR 2.8
#     - SR 2.9
#     - SR 7.1
#     - SR 7.2
#   - ISM
#     - 0988
#     - 1405
#   - ISO27001-2013
#     - A.12.1.3
#     - A.12.4.1
#     - A.12.4.2
#     - A.12.4.3
#     - A.12.4.4
#     - A.12.7.1
#     - A.17.2.1
#   - NERC-CIP
#     - CIP-003-8 R5.2
#     - CIP-004-6 R3.3
#   - NIST
#     - CM-6(a)
#     - AU-4(1)
#     - AU-9(2)
#   - NIST-CSF
#     - PR.DS-4
#     - PR.PT-1
#   - OSPP
#     - FAU_GEN.1.1.c
#   - OS-SRG
#     - SRG-OS-000479-GPOS-00224
#     - SRG-OS-000480-GPOS-00227
#     - SRG-OS-000342-GPOS-00133
#
#################################################################
{%- set stig_id = 'rsyslog_remote_loghost' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        -------------------------------------------
        The rsyslog service must be configured to
        send logs to a remote log server
        -------------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}

Why Skip ({{ stig_id }}):
  test.show_notification:
    - text: |
        --------------------------------------------------
        Configuration of log-collection to a remote
        syslog-server is an inherently site-local
        configuration-task. Many organizations accomplish
        this control-item using tools other than rsyslog.

        This "task" exists solely to act as a reminder for
        why a "global" configuration tool is inappropriate
        for this configuration-task.
        --------------------------------------------------
{%- endif %}
