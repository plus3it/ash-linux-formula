#Install authconfig and update system authentication resources

pkg_authconfig:
  pkg.installed:
    - name: authconfig

cmd_authconfig:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
    - require:
      - pkg: pkg_authconfig
    - unless:
      - 'test -f /etc/pam.d/system-auth-ac'
      - 'test -f /etc/pam.d/password-auth-ac'
