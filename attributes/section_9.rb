# xccdf_org.cisecurity.benchmarks_rule_9.1.1_L1_Ensure_Windows_Firewall_Domain_Firewall_state_is_set_to_On_recommended
default['windows_config']['firewall']['9.1.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile',
  'reg_name' => 'EnableFirewall',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.2_L1_Ensure_Windows_Firewall_Domain_Inbound_connections_is_set_to_Block_default
default['windows_config']['firewall']['9.1.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile',
  'reg_name' => 'DefaultInboundAction',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.3_L1_Ensure_Windows_Firewall_Domain_Outbound_connections_is_set_to_Allow_default
default['windows_config']['firewall']['9.1.3'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile',
  'reg_name' => 'DefaultOutboundAction',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.4_L1_Ensure_Windows_Firewall_Domain_Settings_Display_a_notification_is_set_to_No
default['windows_config']['firewall']['9.1.4'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile',
  'reg_name' => 'DisableNotifications',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.5_L1_Ensure_Windows_Firewall_Domain_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewalldomainfw.log
default['windows_config']['firewall']['9.1.5'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
  'reg_name' => 'LogFilePath',
  'type' => :string,
  'data' => '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.6_L1_Ensure_Windows_Firewall_Domain_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater
default['windows_config']['firewall']['9.1.6'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
  'reg_name' => 'LogFileSize',
  'type' => :dword,
  'data' => '16384',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.7_L1_Ensure_Windows_Firewall_Domain_Logging_Log_dropped_packets_is_set_to_Yes
default['windows_config']['firewall']['9.1.7'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
  'reg_name' => 'LogDroppedPackets',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.1.8_L1_Ensure_Windows_Firewall_Domain_Logging_Log_successful_connections_is_set_to_Yes
default['windows_config']['firewall']['9.1.8'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
  'reg_name' => 'LogSuccessfulConnections',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.1_L1_Ensure_Windows_Firewall_Private_Firewall_state_is_set_to_On_recommended
default['windows_config']['firewall']['9.2.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile',
  'reg_name' => 'EnableFirewall',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.2_L1_Ensure_Windows_Firewall_Private_Inbound_connections_is_set_to_Block_default
default['windows_config']['firewall']['9.2.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile',
  'reg_name' => 'DefaultInboundAction',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.3_L1_Ensure_Windows_Firewall_Private_Outbound_connections_is_set_to_Allow_default
default['windows_config']['firewall']['9.2.3'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile',
  'reg_name' => 'DefaultOutboundAction',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.4_L1_Ensure_Windows_Firewall_Private_Settings_Display_a_notification_is_set_to_No
default['windows_config']['firewall']['9.2.4'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile',
  'reg_name' => 'DisableNotifications',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.5_L1_Ensure_Windows_Firewall_Private_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallprivatefw.log
default['windows_config']['firewall']['9.2.5'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
  'reg_name' => 'LogFilePath',
  'type' => :string,
  'data' => '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.6_L1_Ensure_Windows_Firewall_Private_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater
default['windows_config']['firewall']['9.2.6'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
  'reg_name' => 'LogFileSize',
  'type' => :dword,
  'data' => '16384',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.7_L1_Ensure_Windows_Firewall_Private_Logging_Log_dropped_packets_is_set_to_Yes
default['windows_config']['firewall']['9.2.7'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
  'reg_name' => 'LogDroppedPackets',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.2.8_L1_Ensure_Windows_Firewall_Private_Logging_Log_successful_connections_is_set_to_Yes
default['windows_config']['firewall']['9.2.8'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
  'reg_name' => 'LogSuccessfulConnections',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.1_L1_Ensure_Windows_Firewall_Public_Firewall_state_is_set_to_On_recommended
default['windows_config']['firewall']['9.3.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile',
  'reg_name' => 'EnableFirewall',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.2_L1_Ensure_Windows_Firewall_Public_Inbound_connections_is_set_to_Block_default
default['windows_config']['firewall']['9.3.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile',
  'reg_name' => 'DefaultInboundAction',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.3_L1_Ensure_Windows_Firewall_Public_Outbound_connections_is_set_to_Allow_default
default['windows_config']['firewall']['9.3.3'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile',
  'reg_name' => 'DefaultOutboundAction',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.4_L1_Ensure_Windows_Firewall_Public_Settings_Display_a_notification_is_set_to_No
default['windows_config']['firewall']['9.3.4'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile',
  'reg_name' => 'DisableNotifications',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.5_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_firewall_rules_is_set_to_No
default['windows_config']['firewall']['9.3.5'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile',
  'reg_name' => 'AllowLocalPolicyMerge',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.6_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_connection_security_rules_is_set_to_No
default['windows_config']['firewall']['9.3.6'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile',
  'reg_name' => 'AllowLocalIPsecPolicyMerge',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.7_L1_Ensure_Windows_Firewall_Public_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallpublicfw.log
default['windows_config']['firewall']['9.3.7'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
  'reg_name' => 'LogFilePath',
  'type' => :string,
  'data' => '%systemroot%\\system32\\logfiles\\firewall\\publicfw.log',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.8_L1_Ensure_Windows_Firewall_Public_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater
default['windows_config']['firewall']['9.3.8'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
  'reg_name' => 'LogFileSize',
  'type' => :dword,
  'data' => '16384',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.9_L1_Ensure_Windows_Firewall_Public_Logging_Log_dropped_packets_is_set_to_Yes
default['windows_config']['firewall']['9.3.9'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
  'reg_name' => 'LogDroppedPackets',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_9.3.10_L1_Ensure_Windows_Firewall_Public_Logging_Log_successful_connections_is_set_to_Yes
default['windows_config']['firewall']['9.3.10'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
  'reg_name' => 'LogSuccessfulConnections',
  'type' => :dword,
  'data' => '1',
}
