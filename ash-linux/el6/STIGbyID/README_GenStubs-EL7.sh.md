# Instructions for Generating STIG Stub Handler-Files
1. Download a copy the ZIP-formated Enterprise Linux 7 STIGs (see [IASE site's UNIX/Linux page](http://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx)]
2. Download a copy of the _version 1_ STIG-viewer JAR
  - [Official (DISA) Version](http://iase.disa.mil/stigs/Documents/stig_viewer_1.2.0.jar)
  - [Backup Version](https://redmine.dicelab.net/attachments/download/89/stig_viewer_1.2.0.jar)

  *Note:* the 2.x version of the STIG-viewer currently lacks the ability to do filtered exports. It is critical to the rest of this procedure that you use a 1.x version of the STIG-viewer.
3. Launch the STIG-viewer
  ![Main Screen](https://cloud.githubusercontent.com/assets/7087031/13653867/1fbc9d8c-e622-11e5-88e7-febb515039d3.png)
4. Click on the `Options` entry in the menu-bar
5. Select the `Settings` entry in the `Options` menu
  ![Options Menu](https://cloud.githubusercontent.com/assets/7087031/13653863/1fb8761c-e622-11e5-90fd-59d4fca913a9.png)
6. Ensure that `Display CCI Data` and `Display 800-53 Mapping` are selected and that `Display CCI Description` is unselected
  ![Display Settings](https://cloud.githubusercontent.com/assets/7087031/13653864/1fb8e7f0-e622-11e5-91bc-871c446deb70.png)
7. Click on the `File` entry in the menu-bar
8. Select the `Export` entry in the `File` menu
9. Select the `Current List - CSV (Excel)` entry in the `Export` sub-menu
  ![Export Menu](https://cloud.githubusercontent.com/assets/7087031/13653866/1fba41c2-e622-11e5-9be7-ef9bf31db826.png)
10. Ensure that _only_ the following options are checked:
  - Vuln_Num
  - Severity
  - Rule_ID
  - Rule_Ver
  - Rule_Title
  - Vuln_Discuss

  and
  - Show CCI Ref
  - Show CCI 800-53 Mapping

  ![Export Settings](https://cloud.githubusercontent.com/assets/7087031/13653865/1fb99eb6-e622-11e5-9117-800038c9121b.png)
11. Click on the `Export` button
12. Edit the exported file:
  - Replace all occurrences of `","` with `|`
  - Delete all occurrences of line-leading `"`
  - Delete all occurrences of line-ending `"`
13. Navigate into the directory that will contain your state-file tree
14. Ensure that the `cat1`, `cat2` and `cat3` sub-directories each exists
15. Execute the script, passing the name of the edited export-file as the only argument
