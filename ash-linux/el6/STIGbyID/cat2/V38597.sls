# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38597
# Finding ID:	V-38597
# Version:	RHEL-06-000079
# Finding Level:	Medium
#
#     The system must limit the ability of processes to have simultaneous 
#     write and execute access to memory. ExecShield uses the segmentation 
#     feature on all x86 systems to prevent execution in memory higher than 
#     a certain address. It writes an address as a limit in the code 
#     segment descriptor, to control ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
{%- set stigId = 'V38597' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/sysctl.conf' %}
{%- set parmName = 'kernel.exec-shield' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(chkFile, parmName) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} = 1'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ chkFile }}'
    - text:
      - ' '
      - '# Enable exec-shield (per STIG V-38597)'
      - '{{ parmName }} = 1'
{%- endif %}
