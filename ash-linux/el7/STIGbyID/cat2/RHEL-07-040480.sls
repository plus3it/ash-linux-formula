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
{%- set svcName = 'postfix' %}
{%- set cfgFile = '/etc/postfix/main.cf' %}
{%- set parmName = 'smtpd_client_restrictions' %}
{%- set pfxMain = salt.postfix.show_main() %}
{%- set pfxParmStr = pfxMain.get(parmName, '') %}
{%- set pfxStrCdns = " ".join(pfxParmStr.split()) %}
{%- set curPvalu = pfxStrCdns.split(', ') %}
{%- set minPvalu = [
                        'permit_mynetworks',
                        'reject'
                         ] %}
{%- set newPvalu = [] %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
justdoit_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s{{ parmName }} = .*$'
    - repl: '{{ parmName }} = {{ minPvalu|join(", ") }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} = {{ minPvalu|join(", ") }}

service_{{ stig_id }}-{{ cfgFile }}:
  service.running:
    - name: {{ svcName }}
    - watch:
      - file: justdoit_{{ stig_id }}-{{ cfgFile }}
{%- endif %}



###########################################################################
## Doing this The Right Way(TM) - adding STIG-specified tokens to any
## existing tokens that would be present in a non-default PostFix config -
## is costing too much time to complete.
##
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
##
## For now, just adding skip-logic for tenants that need to preserve any
## specifically-configured functionality (and trusting they've already
## accounted for requisite security controls). Code after this block is
## "ideas" to preserve for future improvements...
###########################################################################

{# 
{%- for val in minPvalu %}
  {%- if not val in curPvalu %}
# test_{{ stig_id }}-{{ val }}:
#   cmd.run:
#     - name: 'echo "{{ parmName }} set to ''{{ val }}''"'
#     - cwd: /root
  {%- endif %}
{%- endfor %}
#}
