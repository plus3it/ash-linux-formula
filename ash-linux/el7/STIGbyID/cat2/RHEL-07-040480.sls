# Finding ID:	RHEL-07-040480
# Version:	RHEL-07-040480_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must be configured to prevent unrestricted mail relaying.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040480' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set postfixMain = postfix.show_main() %}
{%- set postfixMainParmList = postfixMain.keys() %}
{%- set parmName = 'smtpd_client_restrictions' %}
{%- set parmValuList = [
                        'permit_mynetworks',
                        'reject'
                         ] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

###########################################################################
## Can't sort the actual coding, right now, but implementing the following
## should produce the desired results:
##
## 1) Get parms & vals (normal contents of postfix's main.cf file)
##    * Use postfix.show_main
## 2) Extract available config-parms as a key-list
##    * Use keys() against data-struct from #1
## 3) Extract current value of 'smtpd_client_restrictions' (if present)
##    * Probably want to handle as list to ease matching and rule-insertion
## 4) If prescribed-values not present in value-list, append prescribed
##    values to end of current list-contents
## 5) Convert value-list to comma-delimited string
## 6) Set parameter's value to comma-delimited string's content
##    * Use postfix.set_main
## 7) Probably need to reload postfix since postfix.set_main seems to only
##    modify config-contents not running-config.
###########################################################################
