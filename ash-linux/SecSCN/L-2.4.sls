# Module to address findings in SecSCAN 6.3 module L2-4
#
# Summary: Ensure tighter permissions on critical system files
#
# Origin: Guidance for this module is derived from the "CIS Red Hat
#         Enterprise Linux Benchmark v1.1, Chapter 7, April 2008."
#
# Note 1: Application of this module will change permissions on a 
#         number of files throughout the system. These mode changes 
#         will cause security suites that verify RPM-owned files' 
#         mode-settings to mark the respective tests as FAILED. Do 
#         not apply this layer/module unless absolutely required by 
#         program's security assessor.
#
# Note 2: CIS guidance has been updated since last SecSCAN update
#         (2012). Security tool should be upgraded to consult "CIS
#         Red Hat Enterprise Linux 6 Benchmark v1.3.0".
#
############################################################

{%- set secscanId = 'L2-4' %}
{%- set helperLoc = 'ash-linux/SecSCN/files' %}

cmd_{{ secscanId }}-describe:
  cmd.run:
    - name: 'printf "*************************************************\n* Apply file ownership and mode recommendations *\n* from CIS Red Hat Enterprise Linux Benchmark   *\n* v1.1, Chapter 7 (April 2008)                  *\n*************************************************\n"'

{%- set mode_0444 = [
  '/etc/.login',
  '/etc/X11/Xservers',
  '/etc/bashrc',
  '/etc/csh.cshrc',
  '/etc/csh.login',
  '/etc/hosts',
  '/etc/inetd.conf',
  '/etc/mail/sendmail.cf',
  '/etc/mail/submit.cf',
  '/etc/netmasks',
  '/etc/networks',
  '/etc/profile',
  '/etc/services',
  '/etc/shells',
  ]
%}

{%- for modeset_0444 in mode_0444 %}
  {%- if salt['file.file_exists'](modeset_0444) %}

setmode_{{ modeset_0444 }}:
  file.managed:
    - name: '{{ modeset_0444 }}'
    - mode: '0444'

  {%- endif %}
{%- endfor %}
