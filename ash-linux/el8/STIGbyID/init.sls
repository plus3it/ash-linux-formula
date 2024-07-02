include:
  - ash-linux.el8.STIGbyID.cat1
  - ash-linux.el8.STIGbyID.cat2
  - ash-linux.el8.STIGbyID.cat3


Print ash-linux el8 stig baseline help:
  test.show_notification:
    - text: |
        The full, item-by-item `ash-linux.stig` baseline for EL8 is known to
        "over-harden" some systems to the point that they cannot be used for
        their intended workloads.

        Use this content at your own risk.

        If you choose to use this content and it causes issues for you, you can
        block the configuration of some items by setting up exclusions in the
        Pillar-content for this project. See the `skip-stigs` setting in the
        project's `pillar.example` file.
