# xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled:
default['security_options']['personalization']['18.1.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization',
  'reg_name' => 'NoLockScreenCamera',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled:
default['security_options']['personalization']['18.1.1.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization',
  'reg_name' => 'NoLockScreenSlideshow',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.1.2.2_L1_Ensure_Allow_input_personalization_is_set_to_Disabled: (L1) Ensure 'Allow input personalization' is set to 'Disabled' (2 failed)
default['security_options']['personalization']['18.1.2.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization',
  'reg_name' => 'AllowInputPersonalization',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled' (Automated)
default['security_options']['personalization']['18.1.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'AllowOnlineTips',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled_MS_only
default['security_options']['uac']['18.2.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd',
  'reg_name' => 'PwdExpirationProtectionEnabled',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled_MS_only
default['security_options']['uac']['18.2.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd',
  'reg_name' => 'AdmPwdEnabled',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters_MS_only
default['security_options']['uac']['18.2.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd',
  'reg_name' => 'PasswordComplexity',
  'type' => :dword,
  'data' => '4',
}

# xccdf_org.cisecurity.benchmarks_rule_18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more_MS_only
default['security_options']['uac']['18.2.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd',
  'reg_name' => 'PasswordLength',
  'type' => :dword,
  'data' => '15',
}

# xccdf_org.cisecurity.benchmarks_rule_18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer_MS_only
default['security_options']['uac']['18.2.6'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd',
  'reg_name' => 'PasswordAgeDays',
  'type' => :dword,
  'data' => '30',
}

# xccdf_org.cisecurity.benchmarks_rule_18.3.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled_MS_only:
default['security_options']['uac']['18.3.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'LocalAccountTokenFilterPolicy',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_Configure_SMB_v1_client_driver_is_set_to_Enabled_Disable_driver:
default['security_options']['smb']['18.3.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10',
  'reg_name' => 'Start',
  'type' => :dword,
  'data' => '4',
}

# xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_Configure_SMB_v1_server_is_set_to_Disabled:
default['security_options']['smb']['18.3.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
  'reg_name' => 'SMB1',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.3.4_L1_Ensure_Enable_Structured_Exception_Handling_Overwrite_Protection_SEHOP_is_set_to_Enabled:
default['security_options']['others']['18.3.4'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
  'reg_name' => 'DisableExceptionChainValidation',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.3.5_L1_Ensure_WDigest_Authentication_is_set_to_Disabled:
default['security_options']['others']['18.3.5'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
  'reg_name' => 'UseLogonCredential',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled:
default['security_options']['others']['18.4.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'AutoAdminLogon',
  'type' => :string,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled:
default['security_options']['mss']['18.4.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters',
  'reg_name' => 'DisableIPSourceRouting',
  'type' => :dword,
  'data' => '2',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled:
default['security_options']['mss']['18.4.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
  'reg_name' => 'DisableIPSourceRouting',
  'type' => :dword,
  'data' => '2',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.4_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled:
default['security_options']['mss']['18.4.4'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
  'reg_name' => 'EnableICMPRedirect',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keepalive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes(recommended)' (Automated)
default['security_options']['mss']['18.4.5'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
  'reg_name' => 'KeepAliveTime',
  'type' => :dword,
  'data' => '300000',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.6_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled:
default['security_options']['mss']['18.4.6'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters',
  'reg_name' => 'nonamereleaseondemand',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled' (Automated)
default['security_options']['mss']['18.4.7'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
  'reg_name' => 'PerformRouterDiscovery',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.8_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled:
default['security_options']['mss']['18.4.8'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager',
  'reg_name' => 'SafeDllSearchMode',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.9_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds:
default['security_options']['mss']['18.4.9'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'ScreenSaverGracePeriod',
  'type' => :string,
  'data' => '5',
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3' (Automated)
default['security_options']['mss']['18.4.10'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters',
  'reg_name' => 'TcpMaxDataRetransmissions',
  'type' => :dword,
  'data' => 3,
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.11_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds:
default['security_options']['mss']['18.4.11'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters',
  'reg_name' => 'TcpMaxDataRetransmissions',
  'type' => :dword,
  'data' => 3,
}

# xccdf_org.cisecurity.benchmarks_rule_18.4.12_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less:
default['security_options']['mss']['18.4.12'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security',
  'reg_name' => 'WarningLevel',
  'type' => :dword,
  'data' => '90',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.4.1_L1_Set_NetBIOS_node_type_to_P-node_Ensure_NetBT_Parameter_NodeType_is_set_to_0x2_2_MS_Only:
default['security_options']['others']['18.5.4.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters',
  'reg_name' => 'NodeType',
  'type' => :dword,
  'data' => '2',
  'data_rollback' => '8',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.4.2_L1_Ensure_Turn_off_multicast_name_resolution_is_set_to_Enabled_MS_Only:
default['security_options']['others']['18.5.4.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
  'reg_name' => 'EnableMulticast',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.5.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'EnableFontProviders',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.8.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled
default['security_options']['others']['18.5.8.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation',
  'reg_name' => 'AllowInsecureGuestAuth',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'AllowLLTDIOOnDomain',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.1a (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.1a'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'AllowLLTDIOOnPublicNet',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.1b (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.1b'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'EnableLLTDIO',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.1c (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.1c'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'ProhibitLLTDIOOnPrivateNet',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.2 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'AllowRspndrOndomain',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.2a (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.2a'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'AllowRspndrOnPublicNet',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.2b (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.2b'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'EnableRspndr',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.9.2c (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.9.2c'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD',
  'reg_name' => 'ProhibitRspndrOnPrivateNet',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.10.2 (L2) Ensure 'Turn off Microsoft PeertoPeer Networking Services' is set to Enabled' (Automated)
default['security_options']['others']['18.5.10.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Peernet',
  'reg_name' => 'Disabled',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.11.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled:
default['security_options']['others']['18.5.11.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
  'reg_name' => 'NC_AllowNetBridge_NLA',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.11.3_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled:
default['security_options']['others']['18.5.11.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
  'reg_name' => 'NC_ShowSharedAccessUI',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.11.4_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled:
default['security_options']['others']['18.5.11.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
  'reg_name' => 'NC_StdDomainUserSetLocation',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.14.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares:
default['security_options']['others']['18.5.14.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths',
  'reg_name' => '\\\*\NETLOGON',
  'type' => :string,
  'data' => 'RequireMutualAuthentication=1, RequireIntegrity=1',
  'data_rollback' => 'RequireMutualAuthentication=1, RequireIntegrity=1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.20.1'] = {
  'reg_key' => 'HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters',
  'reg_name' => 'DisabledComponents',
  'type' => :dword,
  'data' => '255',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.1a (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.20.1a'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars',
  'reg_name' => 'DisableFlashConfigRegistrar',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.1b (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.20.1b'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars',
  'reg_name' => 'DisableInBand802DOT11Registrar',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.1c (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.20.1c'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars',
  'reg_name' => 'DisableUPnPRegistrar',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.1d (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.20.1d'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars',
  'reg_name' => 'DisableWPDRegistrar',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.1e (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (Automated)
default['security_options']['others']['18.5.20.1e'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars',
  'reg_name' => 'EnableRegistrars',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled' (Automated)
default['security_options']['others']['18.5.20.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WCN\UI',
  'reg_name' => 'DisableWcnUi',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.21.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled:
default['security_options']['others']['18.5.21.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy',
  'reg_name' => 'fMinimizeConnections',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.5.21.2 (L2) Ensure 'Prohibit connection to nondomain networks when connected to domain authenticated network' is set to 'Enabled' (MS only) (Automated)
default['security_options']['others']['18.5.21.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy',
  'reg_name' => 'fBlockNonDomain',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.7.1.1 (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled' (Automated)
default['security_options']['others']['18.7.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications',
  'reg_name' => 'NoCloudApplicationNotification',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.3.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled:
default['security_options']['others']['18.8.3.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit',
  'reg_name' => 'ProcessCreationIncludeCmdLine_Enabled',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled:Force Updated Clients' (Automated)
default['security_options']['others']['18.8.4.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters',
  'reg_name' => 'AllowEncryptionOracle',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.4.2_L1_Ensure_Remote_host_allows_delegation_of_non-exportable_credentials_is_set_to_Enabled:
default['security_options']['others']['18.8.4.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation',
  'reg_name' => 'AllowProtectedCreds',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.5.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
  'reg_name' => 'EnableVirtualizationBasedSecurity',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.5.2 (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA protection' (Automated)
default['security_options']['others']['18.8.5.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
  'reg_name' => 'RequirePlatformSecurityFeatures',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.5.3 (NG) Ensure 'Turn On Virtualization Based Security:Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' (Automated)
default['security_options']['others']['18.8.5.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
  'reg_name' => 'HypervisorEnforcedCodeIntegrity',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_18.8.5.4 (NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)' (Automated)
default['security_options']['others']['18.8.5.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
  'reg_name' => 'HVCIMATRequired',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_18.8.5.5 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only) (Automated)
default['security_options']['others']['18.8.5.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
  'reg_name' => 'LsaCfgFlags',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_18.8.5.7 (NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.5.7'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
  'reg_name' => 'configureSystemGuardLaunch',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.14.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical:
default['security_options']['others']['18.8.14.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch',
  'reg_name' => 'DriverLoadPolicy',
  'type' => :dword,
  'data' => '3',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE:
default['security_options']['others']['18.8.21.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
  'reg_name' => 'NoBackgroundPolicy',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE:
default['security_options']['others']['18.8.21.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
  'reg_name' => 'NoGPOListChanges',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.4_L1_Ensure_Continue_experiences_on_this_device_is_set_to_Disabled
default['security_options']['others']['18.8.21.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'EnableCdp',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.5_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled:
default['security_options']['remove']['18.8.21.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'DisableBkGndGroupPolicy',
  'type' => :dword,
  # 'data' => '90',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.1_L1_Ensure_Turn_off_downloading_of_print_drivers_over_HTTP_is_set_to_Enabled:
default['security_options']['others']['18.8.22.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers',
  'reg_name' => 'DisableWebPnPDownload',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\TabletPC',
  'reg_name' => 'PreventHandwritingDataSharing',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.4 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.4'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\Internet Connection Wizard',
  'reg_name' => 'PreventHandwritingDataSharing',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.5_L1_Ensure_Turn_off_Internet_download_for_Web_publishing_and_online_ordering_wizards_is_set_to_Enabled:
default['security_options']['others']['18.8.22.1.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'NoWebServices',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.6_L1_Ensure_Turn_off_printing_over_HTTP_is_set_to_Enabled:
default['security_options']['others']['18.8.22.1.6'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers',
  'reg_name' => 'DisableHTTPPrinting',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.7 (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.7'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\Registration Wizard Control',
  'reg_name' => 'NoRegistration',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.8'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\SearchCompanion',
  'reg_name' => 'DisableContentFileUpdates',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.9 (L2) Ensure 'Turn off the 'Order Prints' picture task' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.9'] = {
  'reg_key' => 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'NoOnlinePrintsWizard',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.10 (L2) Ensure 'Turn off the 'Publish to Web' task for files and folders' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.10'] = {
  'reg_key' => 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'NoPublishingWizard',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.11 (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.11'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client',
  'reg_name' => 'CEIP',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.12 (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.12'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows',
  'reg_name' => 'CEIPEnable',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.13'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting',
  'reg_name' => 'Disabled',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.13a (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.13a'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting',
  'reg_name' => 'DoReport',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic' (Automated)
default['security_options']['others']['18.8.25.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters',
  'reg_name' => 'DevicePKInitEnabled',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.25.1a (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic' (Automated)
default['security_options']['others']['18.8.25.1a'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters',
  'reg_name' => 'DevicePKInitBehavior',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.26.1 (L1) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All' (Automated)
default['security_options']['others']['18.8.26.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection',
  'reg_name' => 'DeviceEnumerationPolicy',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.1 (L2) Ensure 'Disallow copying of user input methods to the system account for signin' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.27.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Control Panel\International',
  # Software\Policies\Microsoft\Control Panel\International
  'reg_name' => 'BlockUserInputMethodsForSignIn',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.28.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.28.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\System',
  'reg_name' => 'BlockUserFromShowingAccountDetailsOnSignin',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled' (Automated)
default['security_options']['others']['18.8.22.1.8'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\SearchCompanion',
  'reg_name' => 'DisableContentFileUpdates',
  'type' => :dword,
  'data' => '1',
}
# xccdf_org.cisecurity.benchmarks_rule_18.8.28.2_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled:
default['security_options']['others']['18.8.28.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'DontDisplayNetworkSelectionUI',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.2_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled:
default['security_options']['others']['18.8.27.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'DontEnumerateConnectedUsers',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.3_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled_MS_only:
default['security_options']['others']['18.8.27.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'EnumerateLocalUsers',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.4_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled:
default['security_options']['others']['18.8.27.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'DisableLockScreenAppNotifications',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.5_L1_Ensure_Turn_off_picture_password_sign-in_is_set_to_Enabled:
default['security_options']['others']['18.8.27.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'BlockDomainPicturePassword',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.6_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled:
default['security_options']['others']['18.8.27.6'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'AllowDomainPINLogon',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.31.1 (L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled' (Automated)
default['security_options']['others']['18.8.31.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'AllowCrossDeviceClipboard',
  'type' => :dword,
  'data' => '0',
}

# # xccdf_org.cisecurity.benchmarks_rule_18.8.31.1 (L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled' (Automated)
# default['security_options']['others']['18.8.31.1'] = {
#   'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
#   'reg_name' => 'AllowCrossDeviceClipboard',
#   'type' => :dword,
#   'data' => '0',
# }

# xccdf_org.cisecurity.benchmarks_rule_18.8.31.2 (L2) Ensure 'Allow upload of User Activities' is set to 'Disabled' (Automated):
default['security_options']['others']['18.8.31.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
  'reg_name' => 'UploadUserActivities',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.1 (L2)Ensure 'Allow network connectivity during connectedstandby (on battery)' is set to 'Disabled' (Automated):
default['security_options']['others']['18.8.34.6.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9',
  'reg_name' => 'DCSettingIndex',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.2 (L2) Ensure 'Allow network connectivity during connectedstandby (plugged in)' is set to 'Disabled' (Automated):
default['security_options']['others']['18.8.34.6.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9',
  'reg_name' => 'ACSettingIndex',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.3_L1_Ensure_Require_a_password_when_a_computer_wakes_on_battery_is_set_to_Enabled:
default['security_options']['others']['18.8.34.6.3'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51',
  'reg_name' => 'DCSettingIndex',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.34.6.4_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled:
default['security_options']['others']['18.8.34.6.4'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51',
  'reg_name' => 'ACSettingIndex',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.35.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled:
default['security_options']['others']['18.8.35.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'fAllowToGetHelp',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.36.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled_MS_only:
default['security_options']['others']['18.8.36.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc',
  'reg_name' => 'EnableAuthEpResolution',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.37.2 (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled:
default['security_options']['others']['18.8.37.2'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows NT\Rpc',
  'reg_name' => 'RestrictRemoteClients',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.47.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled' (Automated)
default['security_options']['others']['18.8.47.5.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy',
  'reg_name' => 'DisableQueryRemoteServer',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.47.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled' (Automated)
default['security_options']['others']['18.8.47.11.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}',
  'reg_name' => 'ScenarioExecutionEnabled',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.49.1 (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled' (Automated):
default['security_options']['others']['18.8.49.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo',
  'reg_name' => 'DisabledByGroupPolicy',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.52.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled' (Automated):
default['security_options']['others']['18.8.52.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient',
  'reg_name' => 'Enabled',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.8.52.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only) (Automated):
default['security_options']['others']['18.8.52.1.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer',
  'reg_name' => 'Enabled',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled' (Automated):
default['security_options']['others']['18.9.4.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager',
  'reg_name' => 'AllowSharedLocalAppData',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.10.1.1_L1_Ensure_Configure_enhanced_anti-spoofing_is_set_to_Enabled:
default['security_options']['others']['18.9.10.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures',
  'reg_name' => 'EnhancedAntiSpoofing',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled' (Automated):
default['security_options']['others']['18.9.12.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Camera',
  'reg_name' => 'AllowCamera',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.13.1 (L2) Ensure 'Turn off cloud optimized content' is set to 'Enabled' (Manual):
default['security_options']['others']['18.9.13.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
  'reg_name' => 'DisableCloudOptimizedContent',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.13.2_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled:
default['security_options']['others']['18.9.13.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
  'reg_name' => 'DisableWindowsConsumerFeatures',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Require_pin_for_pairing_is_set_to_Enabled:
default['security_options']['others']['18.9.14.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect',
  'reg_name' => 'RequirePinForPairing',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.15.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled:
default['security_options']['others']['18.9.15.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI',
  'reg_name' => 'DisablePasswordReveal',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.15.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled:
default['security_options']['others']['18.9.15.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI',
  'reg_name' => 'EnumerateAdministrators',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only_or_Enabled_1_-_Basic:
default['security_options']['others']['18.9.16.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\DataCollection',
  'reg_name' => 'AllowTelemetry',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.2 (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled:Disable Authenticated Proxy usage' (Automated):
default['security_options']['others']['18.9.16.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
  'reg_name' => 'DisableEnterpriseAuthProxy',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.3 (L1) Ensure 'Do not show feedback notifications' is set to Enabled (Automated):
default['security_options']['others']['18.9.16.3'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\DataCollection',
  'reg_name' => 'DisableEnterpriseAuthProxy',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.4_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled:
default['security_options']['others']['18.9.16.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds',
  'reg_name' => 'AllowBuildPreview',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
default['security_options']['others']['18.9.26.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
  'reg_name' => 'Retention',
  'type' => :string,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater:
default['security_options']['others']['18.9.26.1.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
  'reg_name' => 'MaxSize',
  'type' => :dword,
  'data' => '32768',
  'data_rollback' => '32768',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
default['security_options']['others']['18.9.26.2.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
  'reg_name' => 'Retention',
  'type' => :string,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater:
default['security_options']['others']['18.9.26.2.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
  'reg_name' => 'MaxSize',
  'type' => :dword,
  'data' => '196608',
  'data_rollback' => '196608',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
default['security_options']['others']['18.9.26.3.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
  'reg_name' => 'Retention',
  'type' => :string,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater:
default['security_options']['others']['18.9.26.3.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
  'reg_name' => 'MaxSize',
  'type' => :dword,
  'data' => '32768',
  'data_rollback' => '32768',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
default['security_options']['others']['18.9.26.4.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
  'reg_name' => 'Retention',
  'type' => :string,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater:
default['security_options']['others']['18.9.26.4.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
  'reg_name' => 'MaxSize',
  'type' => :dword,
  'data' => '32768',
  'data_rollback' => '32768',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.30.2_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled:
default['security_options']['others']['18.9.30.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer',
  'reg_name' => 'NoDataExecutionPrevention',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.30.3_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled:
default['security_options']['others']['18.9.30.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer',
  'reg_name' => 'NoHeapTerminationOnCorruption',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.30.4_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled:
default['security_options']['others']['18.9.30.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'PreXPSP2ShellProtocolBehavior',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.39.1 (L2) Ensure 'Turn off location' is set to 'Enabled' (Automated):
default['security_options']['others']['18.9.39.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
  'reg_name' => 'DisableLocation',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.43.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled' (Automated):
default['security_options']['others']['18.9.43.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows\Messaging',
  'reg_name' => 'AllowMessageSync',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.44.1_L1_Ensure_Block_all_consumer_Microsoft_account_user_authentication_is_set_to_Enabled:
default['security_options']['others']['18.9.44.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount',
  'reg_name' => 'DisableUserAuth',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.3_L1_Ensure_Configure_local_setting_override_for_reporting_to_Microsoft_MAPS_is_set_to_Disabled:
default['security_options']['others']['18.9.45.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet',
  'reg_name' => 'LocalSettingOverrideSpynetReporting',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.3.2 (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled':
default['security_options']['others']['18.9.45.3.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet',
  'reg_name' => 'SpyNetReporting',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.1_L1_Ensure_Configure_Attack_Surface_Reduction_rules_is_set_to_Enabled:
default['security_options']['others']['18.9.45.4.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR',
  'reg_name' => 'ExploitGuard_ASR_Rules',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2a_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2a'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '3b576869-a4ec-4529-8536-b80a7769e899',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2b_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2b'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => 'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2c_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2c'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2d_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2d'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2e_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2e'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => 'd3e037e1-3eb8-44c8-a917-57927947596d',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2f_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2f'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2g_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2g'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2h_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2h'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '26190899-1602-49e8-8b27-eb1d0a1ce869',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2i_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2i'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2j_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2j'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.1.2k_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured:
default['security_options']['others']['18.9.45.4.1.2k'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules',
  'reg_name' => 'e6db77e5-3df2-4cf1-b95a-636979351e5b',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.4.3.1_L1_Ensure_Prevent_users_and_apps_from_accessing_dangerous_websites_is_set_to_Enabled_Block:
default['security_options']['others']['18.9.45.4.3.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection',
  'reg_name' => 'EnableNetworkProtection',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.5.1 (L2) Ensure 'Enable file hash computation feature' is set to 'Enabled' (Automated):
default['security_options']['others']['18.9.45.5.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine',
  'reg_name' => 'EnableFileHashComputation',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.8.1 (L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled' (Automated):
default['security_options']['others']['18.9.45.8.1'] = {
  'reg_key' => 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection',
  'reg_name' => 'DisableRealtimeMonitoring',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.8.3_L1_Ensure_Turn_on_behavior_monitoring_is_set_to_Enabled:
default['security_options']['others']['18.9.45.8.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
  'reg_name' => 'DisableBehaviorMonitoring',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.10.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled' (Automated): 
default['security_options']['others']['18.9.45.10.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting',
  'reg_name' => 'DisableGenericRePorts',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.11.2_L1_Ensure_Turn_on_e-mail_scanning_is_set_to_Enabled: 
default['security_options']['others']['18.9.45.11.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
  'reg_name' => 'PUAProtection',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.45.15_L1_Ensure_Turn_off_Windows_Defender_AntiVirus_is_set_to_Disabled:
default['security_options']['others']['18.9.45.15'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
  'reg_name' => 'DisableAntiSpyware',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.52.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled:
default['security_options']['others']['18.9.52.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive',
  'reg_name' => 'DisableFileSyncNGSC',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.52.2_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_on_Windows_8.1_is_set_to_Enabled:
default['security_options']['others']['18.9.52.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive',
  'reg_name' => 'DisableFileSync',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled:
default['security_options']['others']['18.9.58.2.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'DisablePasswordSaving',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled:
default['security_options']['others']['18.9.58.3.3.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'fDisableCdm',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled:
default['security_options']['others']['18.9.58.3.9.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'fPromptForPassword',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled:
default['security_options']['others']['18.9.58.3.9.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'fEncryptRPCTraffic',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level:
default['security_options']['others']['18.9.58.3.9.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'MinEncryptionLevel',
  'type' => :dword,
  'data' => '3',
  'data_rollback' => '2',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled:
default['security_options']['others']['18.9.58.3.11.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'DeleteTempDirsOnExit',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled:
default['security_options']['others']['18.9.58.3.11.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
  'reg_name' => 'PerSessionTempDir',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.59.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled:
default['security_options']['others']['18.9.59.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds',
  'reg_name' => 'DisableEnclosureDownload',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled:
default['security_options']['others']['18.9.6.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'MSAOptional',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.60.2_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled:
default['security_options']['others']['18.9.60.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search',
  'reg_name' => 'AllowIndexingEncryptedStoresOrItems',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.10.1_L1_Ensure_Scan_removable_drives_is_set_to_Enabled:
default['security_options']['others']['18.9.76.10.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan',
  'reg_name' => 'DisableRemovableDriveScanning',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled:
default['security_options']['others']['18.9.8.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer',
  'reg_name' => 'NoAutoplayfornonVolume',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands:
default['security_options']['others']['18.9.8.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'NoAutorun',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives:
default['security_options']['others']['18.9.8.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
  'reg_name' => 'NoDriveTypeAutoRun',
  'type' => :dword,
  'data' => '255',
  'data_rollback' => '145',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.1_L1_Ensure_Configure_Default_consent_is_set_to_Enabled_Always_ask_before_sending_data:
default['security_options']['others']['18.9.81.2.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent',
  'reg_name' => 'DefaultConsent',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.3_L1_Ensure_Automatically_send_memory_dumps_for_OS-generated_error_reports_is_set_to_Disabled:
default['security_options']['others']['18.9.81.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting',
  'reg_name' => 'AutoApproveOSDumps',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled:
default['security_options']['others']['18.9.85.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer',
  'reg_name' => 'EnableUserControl',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled:
default['security_options']['others']['18.9.85.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer',
  'reg_name' => 'AlwaysInstallElevated',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.86.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled:
default['security_options']['others']['18.9.86.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system',
  'reg_name' => 'DisableAutomaticRestartSignOn',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.95.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled:
default['security_options']['others']['18.9.95.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'reg_name' => 'EnableScriptBlockLogging',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.95.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled:
default['security_options']['others']['18.9.95.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription',
  'reg_name' => 'EnableTranscripting',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled:
default['security_options']['others']['18.9.97.1.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
  'reg_name' => 'AllowBasic',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled:
default['security_options']['others']['18.9.97.1.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
  'reg_name' => 'AllowUnencryptedTraffic',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled:
default['security_options']['others']['18.9.97.1.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
  'reg_name' => 'AllowDigest',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled:
default['security_options']['others']['18.9.97.2.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
  'reg_name' => 'AllowBasic',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.2.3_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled:
default['security_options']['others']['18.9.97.2.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
  'reg_name' => 'AllowUnencryptedTraffic',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.2.4_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled:
default['security_options']['others']['18.9.97.2.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
  'reg_name' => 'DisableRunAs',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.2_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled:
default['security_options']['others']['18.9.101.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
  'reg_name' => 'NoAutoUpdate',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.3_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day:
default['security_options']['others']['18.9.101.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
  'reg_name' => 'ScheduledInstallDay',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled:
default['security_options']['others']['18.9.101.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
  'reg_name' => 'NoAutoRebootWithLoggedOnUsers',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}
