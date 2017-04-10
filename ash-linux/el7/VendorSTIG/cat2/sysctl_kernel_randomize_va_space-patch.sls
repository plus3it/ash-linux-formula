# Finding ID:
# Version:		sysctl_kernel_randomize_va_space
# SRG ID:
# Finding Level:	medium
#
# Rule Summary:
#	Address space layout randomization (ASLR) makes it more
#	difficult for an attacker to predict the location of
#	attack code they have introduced into a process's address
#	space during an attempt at exploitation. Additionally,
#	ASLR makes it more difficult for an attacker to know the
#	location of existing code in order to re-purpose it using
#	return oriented programming (ROP) techniques.
#
# CCI-1551
#    NIST SP 800-53 Revision 4 :: SC-30(2)
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.6.1
#
# Special note:
#	This state is designed only to patch what has been done
#	by a prior running of the `oscap` utility with the
#	 `--remediate` mode enabled
#
#	Filed Red Hat Bugzilla: 1423016
#
#################################################################
{%- set stig_id = 'sysctl_kernel_randomize_va_space' %}
{%- set helperLoc = 'ash-linux/el7/VendorSTIG/cat2/files' %}
{%- set badVal = 'kernelrandomizevaspace' %}
{%- set gudVal = 'kernel.randomize_va_space' %}
{%- set fixFiles = salt['cmd.shell']('find /etc -type f ! -name "*.bak" | xargs grep -l ' + badVal).split('\n') %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for ruleFile in fixFiles %}
  {%- if ruleFile == '' %}
    {%- set ruleFile = '/etc/sysctl.d/aslr.conf' %}
touch_{{ stig_id }}-{{ ruleFile }}:
  file.touch:
    - name: '{{ ruleFile }}'
file_{{ stig_id }}-{{ ruleFile }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^{{ gudVal }}.*'
    - repl: '{{ gudVal }} = 2'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ gudVal }} = 2
    - require:
      - file: touch_{{ stig_id }}-{{ ruleFile }}
  {%- else %}
file_{{ stig_id }}-{{ ruleFile }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '{{ badVal }}'
    - repl: '{{ gudVal }}'
  {%- endif %}
{%- endfor %}
