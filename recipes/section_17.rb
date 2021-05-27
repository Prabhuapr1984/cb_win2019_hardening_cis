# Cookbook:: cb_win2019_hardening_cis
# Recipe:: section_17
#
# Copyright:: 2020, The Authors, All Rights Reserved.

# Rename Advanced Audit files (csv) - if exists
powershell_script 'Rename_Audit_File' do
  code <<-EOH
  $ErrorActionPreference = 'SilentlyContinue'
  $filenameFormat = "audit" + "" + (Get-Date -Format "yyyy-MM-dd")
  Get-Item -Path "C:\\Windows\\System32\\GroupPolicy\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv" |Rename-Item -NewName $filenameFormat
  EOH
  only_if { ::File.exist?('C:\\Windows\\System32\\GroupPolicy\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv') }
end

# Deploying Advance Audit file [section_17]
template 'c:/windows/temp/audit.csv' do
  source 'audit.erb'
  sensitive true
  # notifies :run, "powershell_script[Deploy_section_17_csv]", :immediately
end

powershell_script 'Deploy_section_17_csv' do
  code <<-EOH
    auditpol /restore /file:c:/windows/temp/audit.csv
    gpupdate /force
  EOH
  # action :nothing
end

# # xccdf_org.cisecurity.benchmarks_rule_17.1.1_L1_Ensure_Audit_Credential_Validation_is_set_to_Success_and_Failure:
# audit_policy 'Audit Credential Validation - Success, Failure' do
#   subcategory 'Credential Validation'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.2.1_L1_Ensure_Audit_Application_Group_Management_is_set_to_Success_and_Failure:
# audit_policy 'Audit Application Group Management - No Auditing' do
#   subcategory 'Application Group Management'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.2.2_L1_Ensure_Audit_Computer_Account_Management_is_set_to_Success_and_Failure:
# audit_policy 'Audit Computer Account Management - Success, Failure' do
#   subcategory 'Computer Account Management'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.2.4_L1_Ensure_Audit_Other_Account_Management_Events_is_set_to_Success_and_Failure:
# audit_policy 'Audit Other Account Management Events - Success, Failure' do
#   subcategory 'Other Account Management Events'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.2.5_L1_Ensure_Audit_Security_Group_Management_is_set_to_Success:
# audit_policy 'Audit Security Group Management - Success' do
#   subcategory 'Security Group Management'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.2.6_L1_Ensure_Audit_User_Account_Management_is_set_to_Success_and_Failure:
# audit_policy 'Audit User Account Management - Success, Failure' do
#   subcategory 'User Account Management'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success: (L1) Ensure 'Audit PNP Activity' is set_to_Success:
# audit_policy 'Audit Policy Plug and Play Events - Success' do
#   subcategory 'Plug and Play Events'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.3.2_L1_Ensure_Audit_Process_Creation_is_set_to_Success:
# audit_policy 'Audit Process Creation - Success' do
#   subcategory 'Process Creation'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.5.1_L1_Ensure_Audit_Account_Lockout_is_set_to_Failure:
# audit_policy 'Audit Account Lockout - Failure' do
#   subcategory 'Account Lockout'
#   flag 'Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.5.2_L1_Ensure_Audit_Group_Membership_is_set_to_Success: (L1) Ensure 'Audit Group Membership' is set to 'Success'
# audit_policy 'Audit Policy Group Membership - Success' do
#   subcategory 'Group Membership'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.5.3_L1_Ensure_Audit_Logoff_is_set_to_Success:
# audit_policy 'Audit Logoff - Success' do
#   subcategory 'Logoff'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.5.4_L1_Ensure_Audit_Logon_is_set_to_Success_and_Failure:
# audit_policy 'Audit Logon - Success, Failure' do
#   subcategory 'Logon'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.5.5_L1_Ensure_Audit_Other_LogonLogoff_Events_is_set_to_Success_and_Failure:
# audit_policy 'Audit Other Logon/Logoff Events - Success, Failure' do
#   subcategory 'Other Logon/Logoff Events'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.5.6_L1_Ensure_Audit_Special_Logon_is_set_to_Success:
# audit_policy 'Audit Special Logon - Success' do
#   subcategory 'Special Logon'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.6.1_L1_Ensure_'Audit Detailed File Share' is set to include 'Failure': (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'
# audit_policy 'Audit Detailed File Share - Failure' do
#   subcategory 'Detailed File Share'
#   flag 'Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.6.2_L1_Ensure 'Audit File Share' is set to 'Success and Failure'
# audit_policy 'Audit File Share - Failure - Success and Failure' do
#   subcategory 'File Share'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.6.3_L1_Ensure_Audit_Other_Object_Access_Events_is_set_to_Success_and_Failure
# audit_policy 'Audit Other Object Access Events - Success, Failure' do
#   subcategory 'Other Object Access Events'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.6.2_L1_Ensure_Audit_Removable_Storage_is_set_to_Success_and_Failure
# audit_policy 'Audit Removable Storage - Success, Failure' do
#   subcategory 'Removable Storage'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.7.1_L1_Ensure_Audit_Audit_Policy_Change_is_set_to_Success_and_Failure:
# audit_policy 'Audit Audit Policy Change - Success, Failure' do
#   subcategory 'Audit Policy Change'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.7.2_L1_Ensure_Audit_Authentication_Policy_Change_is_set_to_Success:
# audit_policy 'Audit Authentication Policy Change - Success' do
#   subcategory 'Authentication Policy Change'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.7.3_L1_Ensure_Audit_Authorization_Policy_Change_is_set_to_Success:
# audit_policy 'Audit Authorization Policy Change - Success' do
#   subcategory 'Authorization Policy Change'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.7.4 (L1) Ensure 'Audit MPSSVC RuleLevel Policy Change' is set to 'Success and Failure' (Automated): (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
# audit_policy 'MPSSVC Rule-Level Policy Change- Success' do
#   subcategory 'MPSSVC Rule-Level Policy Change'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure' (Automated): (L1) Ensure Audit Other Policy Change Events is set to 'Success'
# audit_policy 'Other Policy Change Events - Failure' do
#   subcategory 'Other Policy Change Events'
#   flag 'Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.8.1_L1_Ensure_Audit_Sensitive_Privilege_Use_is_set_to_Success_and_Failure:
# audit_policy 'Audit Sensitive Privilege - Success and Failure' do
#   subcategory 'Sensitive Privilege Use'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.9.1_L1_Ensure_Audit_IPsec_Driver_is_set_to_Success_and_Failure:
# audit_policy 'Audit IPsec Driver - Success, Failure' do
#   subcategory 'IPsec Driver'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.9.2_L1_Ensure_Audit_Other_System_Events_is_set_to_Success_and_Failure:
# audit_policy 'Audit Other System Events - Success and Failure' do
#   subcategory 'Other System Events'
#   flag 'Success and Failure'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.9.3_L1_Ensure_Audit_Security_State_Change_is_set_to_Success:
# audit_policy 'Audit Security State Change - Success' do
#   subcategory 'Security State Change'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.9.4_L1_Ensure_Audit_Security_System_Extension_is_set_to_Success:
# audit_policy 'Audit Security System Extension - Success' do
#   subcategory 'Security System Extension'
#   flag 'Success'
#   action :set
# end

# # xccdf_org.cisecurity.benchmarks_rule_17.9.5_L1_Ensure_Audit_System_Integrity_is_set_to_Success_and_Failure:
# audit_policy 'Audit System Integrity - Success and Failure' do
#   subcategory 'System Integrity'
#   flag 'Success and Failure'
#   action :set
# end
