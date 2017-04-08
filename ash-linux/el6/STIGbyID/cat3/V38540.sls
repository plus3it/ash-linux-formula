# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38540
# Rule ID:		audit_network_modifications
# Finding ID:		V-38540
# Version:		RHEL-06-000182
# SCAP Security ID:	CCE-26648-6
# Finding Level:	Low
#
#     The audit system must be configured to audit modifications to the
#     systems network configuration. The network environment should not be
#     modified by anything other than administrator action. Any change to
#     network parameters should be audited.
#
############################################################

{%- set stig_id = '38540' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set audRulCfg = '/etc/audit/audit.rules' %}
###########################################################################
## From '/usr/lib/python2.6/site-packages/salt/modules/yumpkg.py'        ##
## __ARCHES_64 = ('x86_64', 'athlon', 'amd64', 'ia32e', 'ia64', 'geode') ##
## __ARCHES_32 = ('i386', 'i486', 'i586', 'i686')                        ##
###########################################################################
{%- if grains['cpuarch'] == 'x86_64' or grains['cpuarch'] == 'athlon' or grains['cpuarch'] == 'amd64'%}
  {%- set audFam = 'b64' %}
{%- elif grains['cpuarch'] == 'i386' or grains['cpuarch'] == 'i486' or grains['cpuarch'] == 'i586' or grains['cpuarch'] == 'i686' %}
  {%- set audFam = 'b32' %}
{%- endif %}
{%- set sPattern = '-a always,exit -F arch=' + audFam + ' -S sethostname -S setdomainname -k audit_network_modifications' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: /root

######################################################################
# Will probably want to look at method to do all the edits in one pass:
# Current method limits rollback capability
######################################################################
{%- if not salt['cmd.shell']('grep -c -E -e "' + sPattern + '" ' + audRulCfg , output_loglevel='quiet') == '0' %}
file_V{{ stig_id }}-sethostname_setdomainname:
  cmd.run:
    - name: 'echo "Appropriate audit-rule already present"'
{%- else %}
file_V{{ stig_id }}-sethostname_setdomainname:
  file.append:
    - name: '{{ audRulCfg }}'
    - text: |

        # Audit all network configuration modifications (per STIG-ID V-{{ stig_id }})
        {{ sPattern }}
{%- endif %}

# Monitoring of networking files and directories
{%- set files = [
    '/etc/issue',
    '/etc/issue.net',
    '/etc/hosts',
    '/etc/sysconfig/network',
    '/etc/sysconfig/network-scripts/',
] %}
{%- set audit_options = '-p wa -k audit_network_modifications' %}

{%- for file in files %}
  {%- set fullRule = '-w' + ' ' + file + ' ' + audit_options %}

fileExists_V{{ stig_id }}-auditRules_{{ file }}:
  cmd.run:
    - name: 'echo "Appropriate audit rule already in place"'
    - onlyif: 'grep -c -E -e "{{ fullRule }}" {{ audRulCfg }}'

fileAdd_V{{ stig_id }}-auditRules_{{ file }}:
  file.append:
    - name: '{{ audRulCfg }}'
    - text: |

        # Monitor {{ file }} for changes (per STIG-ID V-{{ stig_id }})
        {{ fullRule }}
    - unless: 'grep -c -E -e "{{ fullRule }}" {{ audRulCfg }}'

{%- endfor %}
