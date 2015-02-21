#Install authconfig, update system authentication resources, and backup
#critical authentication files

pkg_authconfig:
  pkg.installed:
    - name: authconfig

file_system-auth:
  file.managed:
    - name: /etc/pam.d/system-auth
    - replace: false
    - require:
      - pkg: pkg_authconfig
    - unless:
      - 'test -f /etc/pam.d/system-auth-ac'

file_password-auth:
  file.managed:
    - name: /etc/pam.d/password-auth
    - replace: false
    - require:
      - pkg: pkg_authconfig
    - unless:
      - 'test -f /etc/pam.d/password-auth-ac'

cmd_authconfig:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
    - require:
      - file: file_system-auth
      - file: file_password-auth
    - unless:
      - 'test -f /etc/pam.d/system-auth-ac'
      - 'test -f /etc/pam.d/password-auth-ac'

file_system-auth-ac:
  file.managed:
    - name: /etc/pam.d/system-auth-ac
    - replace: false
    - backup: minion
    - require:
      - cmd: cmd_authconfig

file_password-auth-ac:
  file.managed:
    - name: /etc/pam.d/password-auth-ac
    - replace: false
    - backup: minion
    - require:
      - cmd: cmd_authconfig
