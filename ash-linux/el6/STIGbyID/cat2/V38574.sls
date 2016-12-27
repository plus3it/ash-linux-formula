# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38574
# Finding ID:	V-38574
# Version:	RHEL-06-000062
# Finding Level:	Medium
#
#     The system must use a FIPS 140-2 approved cryptographic hashing 
#     algorithm for generating account password hashes (system-auth). Using 
#     a stronger hashing algorithm makes password cracking attacks more 
#     difficult.
#
#  CCI: CCI-000803
#  NIST SP 800-53 :: IA-7
#  NIST SP 800-53A :: IA-7.1
#  NIST SP 800-53 Revision 4 :: IA-7
#
############################################################

include:
  - ash-linux.authconfig

{%- set stig_id = '38574' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

# Update pam_unix.so settings in /etc/pam.d/system-auth
{%- set checkFile = '/etc/pam.d/system-auth-ac' %}
{%- set hash_type = 'sha512' %}

{%- macro enforce_passwordhash(stig_id, file, hash_type) %}
replace_md5_V{{ stig_id }}-{{ hash_type }}:
  file.replace:
    - name: {{ file }}
    - pattern: ' md5'
    - repl: ' {{ hash_type }}'
    - onlyif: 'grep -E -e "^[ \t]*password[ \t]+sufficient[ \t]+pam_unix.so.*[ \t]md5" {{ file }}'

add_V{{ stig_id }}-{{ hash_type }}:
  file.replace:
    - name: {{ file }}
    - pattern: '^(?P<srctok>password[ \t]*sufficient[ \t]*pam_unix.so.*$)'
    - repl: '\g<srctok> {{ hash_type }}'
    - onlyif:
      - 'test $(grep -c -E -e "^[ \t]*password[ \t]+sufficient[ \t]+pam_unix.so.*[ \t]md5" {{ file }}) -eq 0'
      - 'test $(grep -c -E -e "^[ \t]*password[ \t]+sufficient[ \t]+pam_unix.so.*[ \t]{{ hash_type }}" {{ file }}) -eq 0'

notify_V{{ stig_id }}-{{ hash_type }}:
  cmd.run:
    - name: 'echo "Password hash set to {{ hash_type }} (per STIG ID V-{{ stig_id }})"'
{%- endmacro %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

# Update /etc/sysconfig/authconfig
file_V{{ stig_id }}-repl:
  file.replace:
    - name: /etc/sysconfig/authconfig
    - pattern: '^PASSWDALGORITHM.*$'
    - repl: 'PASSWDALGORITHM={{ hash_type }}'
    - onlyif:
      - 'test -f /etc/sysconfig/authconfig'

{%- if salt.file.file_exists(checkFile) %}

#file {{ checkFile }} exists

  {%- if salt.file.search(checkFile, ' pam_unix.so ') %}

#pam_unix.so found in /etc/pam.d/system-auth-ac

    {%- if salt.file.search(checkFile, ' ' + hash_type) %}

#{{ hash_type }} already set
set_V{{ stig_id }}-sha512:
  cmd.run:
    - name: 'echo "Passwords already require SHA512 encryption"'

    {%- else %}

#{{ hash_type }} not found
#use macro to ensure the required hash type is in place
{{ enforce_passwordhash(stig_id, checkFile, hash_type) }}

    {%- endif %}

  {%- else %}
  
#pam_unix.so not found in /etc/pam.d/system-auth-ac; do nothing

  {%- endif %}

{%- else %}

#file did not exist when jinja templated the file; file will be configured 
#by authconfig.sls in the include statement.
#use macro to ensure the required hash type is in place
{{ enforce_passwordhash(stig_id, checkFile, hash_type) }}

{%- endif %}
