# Finding ID:
# Version:		sysctl_kernel_ipv6_disable
# SRG ID:
# Finding Level:	medium
#
# Rule Summary:
#	Any unnecessary network stacks - including IPv6 - should
#	be disabled, to reduce the vulnerability to exploitation.
#	Disable IPv6 on all network interfaces in a manner that
#	allows other services and system functionality requiring
#	the IPv6 stack loaded to work.
#
# CCI-1551
#    NIST SP 800-53 Revision 4 :: CM-7
#    CIS RHEL 7 Benchmark 1.1.0 :: 4.4.2
#
#################################################################
{%- set stig_id = 'sysctl_kernel_ipv6_disable' %}
{%- set helperLoc = 'ash-linux/el7/VendorSTIG/cat2/files' %}
{%- set ruleFile = '/etc/sysctl.d/ipv6.conf' %}
{%- set parmName = 'net.ipv6.conf.all.disable_ipv6' %}
{%- set parmValu = '1' %}
{%- set postfixParam = 'inet_protocols' %}
{%- set postfixValue = 'ipv4' %}

file_{{ stig_id }}-{{ ruleFile }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^{{ parmName }} = *$'
    - repl: '{{ parmName }} = {{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} = {{ parmValu }}

{%- if not salt.file.file_exists(ruleFile) %}
touch_{{ stig_id }}-{{ ruleFile }}:
  file.touch:
    - name: '{{ ruleFile }}'
    - require_in:
      - file: file_{{ stig_id }}-{{ ruleFile }}
{%- endif %}

# Set Postfix to user only ipv4 when ipv6 is disabled
set_postfix_param_{{ postfixParam }}_{{ stig_id }}:
  module.run:
    - name: postfix.set_main
    - key: {{ postfixParam }}
    - value: {{ postfixValue }}
    - require:
      - file: file_{{ stig_id }}-{{ ruleFile }}
