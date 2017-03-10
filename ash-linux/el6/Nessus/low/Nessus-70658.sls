# Finding URL:	https://www.tenable.com/plugins/index.php?view=single&id=70658
# Family:	Miscellaneous
# Nessus ID:	70658
# Bugtraq ID:	
# CVE ID:	
# Finding Level:	low
#
#     The SSH daemon must be configured to use only strong 
#     encryption-ciphers. Configured ciphers should not allow
#     use of CBC-based modes.
#
############################################################

{%- set stigId = 'Nessus-70658' %}
{%- set helperLoc = 'ash-linux/el6/Nessus/low/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'Ciphers' %}
{%- set parmVal = 'aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,arcfour' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(cfgFile, '^' + parmName)
 %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} {{parmVal }}'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# SSH service must allow only FIPS 140-2 ciphers (per {{ stigId }})'
      - '{{ parmName }} {{ parmVal }}'
{%- endif %}

