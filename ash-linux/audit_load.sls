# Summary:
#
#    This salt state will apply updates to the audit rules without
#    requiring a system reboot.  The `augenrules --load` command
#    will aggregate the changes in the audit rules files and apply
#    it to the system.
#
####################################################################

pkg_audit:
  pkg.installed:
    - name: audit

cmd_augenrules:
  cmd.run:
    - name: 'augenrules --load'
    - require:
      - pkg: pkg_audit
