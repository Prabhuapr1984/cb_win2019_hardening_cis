# cb_win2019_hardening_cis

# Note:

Disabled the below settings due to unable RDP:

* xccdf_org.cisecurity.benchmarks_rule_9.1.1_L1_Ensure_Windows_Firewall_Domain_Firewall_state_is_set_to_On_recommended
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile EnableFirewall

* xccdf_org.cisecurity.benchmarks_rule_9.2.1_L1_Ensure_Windows_Firewall_Private_Firewall_state_is_set_to_On_recommended:
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile EnableFirewall

* xccdf_org.cisecurity.benchmarks_rule_9.3.1_L1_Ensure_Windows_Firewall_Public_Firewall_state_is_set_to_On_recommended:
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile EnableFirewall

* NOTE:

Incase if you don't have chef still you can leverage the below methods to deploy.


** Group Policy (GPO)
** System center configuration manager (SCCM)
** Manual method

## Step: To apply hardening

Copy the standalone 'standalone.inf.erb' to 'C:\temp\secpol_win2019.inf' and execute the below command using administrative rights.

  Secedit /configure /db C:\Windows\security\database\secpol_win2019.sdb /cfg C:\temp\secpol_win2019.inf /log C:\Windows\security\logs\secpol_win2019.log

## Step: To apply Advance auditing
Copy the 'audit.erb' to 'c:/windows/temp/audit.csv' and execute the below command using administrative rights.

  auditpol /restore /file:c:/windows/temp/audit.csv