# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38651
# Finding ID:	V-38651
# Version:	RHEL-06-000342
# Finding Level:	Low
#
#     The umask value influences the permissions assigned to files when 
#     they are created. A misconfigured umask value could result in files 
#     with excessive permissions that can be read and/or written to by 
#     unauthorized users. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38651' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
 
script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search('/etc/bashrc', '^[   ]*umask[ 	][0-9][0-9]') %}
file_{{ stigId }}-bashrcUmask:
  file.replace:
    - name: '/etc/bashrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
{%- else %}
file_{{ stigId }}-bashrcUmask:
  file.append:
    - name: '/etc/bashrc'
    - text: |
        
        # Umask must be set to "077" (per STIG V-38651)
        umask 077
{%- endif %}

# If AT&T KSH is instelled...
{%- if salt.pkg.version('ksh') %}
  {%- if salt.file.search('/etc/kshrc', '^[   ]*umask') %}
file_{{ stigId }}-kshrcUmask:
  file.replace:
    - name: '/etc/kshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {%- endif %}

  {%- if salt.file.search('/etc/skel/.kshrc', '^[   ]*umask') %}
file_{{ stigId }}-kshrcUmaskSkel:
  file.replace:
    - name: '/etc/skel/.kshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {%- endif %}
{%- endif %}


# If BSD enhanced-KSH is instelled...
{%- if salt.pkg.version('mksh') %}
  {%- if salt.file.search('/etc/mkshrc', '^[   ]*umask') %}
file_{{ stigId }}-mkshrcUmask:
  file.replace:
    - name: '/etc/mkshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {%- endif %}

  {%- if salt.file.search('/etc/skel/.mkshrc', '^[   ]*umask') %}
file_{{ stigId }}-mkshrcUmaskSkel:
  file.replace:
    - name: '/etc/skel/.mkshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {%- endif %}
{%- endif %}
