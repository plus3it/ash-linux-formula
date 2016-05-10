# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38580
# Finding ID:	V-38580
# Version:	RHEL-06-000202
# Finding Level:	Medium
#
#     The audit system must be configured to audit the loading and 
#     unloading of dynamic kernel modules. The addition/removal of kernel 
#     modules can be used to alter the behavior of the kernel and 
#     potentially introduce malicious code into kernel space. It is 
#     important to have an audit trail of modules ...
#
#  CCI: CCI-000172
#  NIST SP 800-53 :: AU-12 c
#  NIST SP 800-53A :: AU-12.1 (iv)
#  NIST SP 800-53 Revision 4 :: AU-12 c
#
############################################################

{%- set stig_id = '38580' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/audit/audit.rules' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

file_V{{ stig_id }}-appendModchk:
  file.append:
    - name: '{{ chkFile }}'
    - text: |
        
        # Monitor dynamic kernel module (un)load (per STIG-ID V-{{ stig_id }}/RHEL-06-000202)
        -w /sbin/insmod -p x -k modules
        -w /sbin/rmmod -p x -k modules
        -w /sbin/modprobe -p x -k modules
{%- if grains['cpuarch'] == 'x86_64' or grains['cpuarch'] == 'amd64' or grains['cpuarch'] == 'athlon' %}
        -a always,exit -F arch=b64 -S init_module -S delete_module -k modules
{%- elif grains['cpuarch'] == 'i386' or grains['cpuarch'] == 'i486' or grains['cpuarch'] == 'i586' or grains['cpuarch'] == 'i686' %}
        -a always,exit -F arch=b32 -S init_module -S delete_module -k modules
{%- endif %}
