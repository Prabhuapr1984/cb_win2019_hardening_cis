# xccdf_org.cisecurity.benchmarks_rule_2.3.1.2_L1_Ensure_Accounts_Block_Microsoft_accounts_is_set_to_Users_cant_add_or_log_on_with_Microsoft_accounts:
default['security_options']['accounts']['2.3.1.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'NoConnectedUser',
  'type' => :dword,
  'data' => '3',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled_MS_only:
# xccdf_org.cisecurity.benchmarks_rule_2.3.1.4_L1_Ensure_Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only_is_set_to_Enabled:
default['security_options']['accounts']['2.3.1.4'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'LimitBlankPasswordUse',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.2.1_L1_Ensure_Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings_is_set_to_Enabled:
default['security_options']['audit']['2.3.2.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'SCENoApplyLegacyAuditPolicy',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.2.2_L1_Ensure_Audit_Shut_down_system_immediately_if_unable_to_log_security_audits_is_set_to_Disabled:
default['security_options']['audit']['2.3.2.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'CrashOnAuditFail',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.4.1_L1_Ensure_Devices_Allowed_to_format_and_eject_removable_media_is_set_to_Administrators:
default['security_options']['devices']['2.3.4.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'AllocateDASD',
  'type' => :string,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.4.2_L1_Ensure_Devices_Prevent_users_from_installing_printer_drivers_is_set_to_Enabled:
default['security_options']['devices']['2.3.4.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers',
  'reg_name' => 'AddPrinterDrivers',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.1_L1_Ensure_Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always_is_set_to_Enabled:
default['security_options']['domainmember']['2.3.6.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
  'reg_name' => 'RequireSignOrSeal',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.2_L1_Ensure_Domain_member_Digitally_encrypt_secure_channel_data_when_possible_is_set_to_Enabled:
default['security_options']['domainmember']['2.3.6.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
  'reg_name' => 'SealSecureChannel',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.3_L1_Ensure_Domain_member_Digitally_sign_secure_channel_data_when_possible_is_set_to_Enabled:
default['security_options']['domainmember']['2.3.6.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
  'reg_name' => 'SignSecureChannel',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.4_L1_Ensure_Domain_member_Disable_machine_account_password_changes_is_set_to_Disabled:
default['security_options']['domainmember']['2.3.6.4'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
  'reg_name' => 'DisablePasswordChange',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.5_L1_Ensure_Domain_member_Maximum_machine_account_password_age_is_set_to_30_or_fewer_days_but_not_0:
default['security_options']['domainmember']['2.3.6.5'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
  'reg_name' => 'MaximumPasswordAge',
  'type' => :dword,
  'data' => '30',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.6_L1_Ensure_Domain_member_Require_strong_Windows_2000_or_later_session_key_is_set_to_Enabled:
default['security_options']['domainmember']['2.3.6.6'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
  'reg_name' => 'RequireStrongKey',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.1_L1_Ensure_Interactive_logon_Do_not_display_last_user_name_is_set_to_Enabled:
default['security_options']['interactivelogon']['2.3.7.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'DontDisplayLastUserName',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.2_L1_Ensure_Interactive_logon_Do_not_require_CTRLALTDEL_is_set_to_Disabled:
default['security_options']['interactivelogon']['2.3.7.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'DisableCAD',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.3_L1_Ensure_Interactive_logon_Machine_inactivity_limit_is_set_to_900_or_fewer_seconds_but_not_0:
default['security_options']['interactivelogon']['2.3.7.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'InactivityTimeoutSecs',
  'type' => :dword,
  'data' => '900',
  'data_rollback' => '1800',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.4_L1_Configure_Interactive_logon_Message_text_for_users_attempting_to_log_on:
default['security_options']['interactivelogon']['2.3.7.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'LegalNoticeText',
  'type' => :string,
  'data' => 'WARNING : You are about to access unauthorised network',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.5_L1_Configure_Interactive_logon_Message_title_for_users_attempting_to_log_on:
default['security_options']['interactivelogon']['2.3.7.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'LegalNoticeCaption',
  'type' => :string,
  'data' => 'unauthorised network',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only) (Automated)
default['security_options']['interactivelogon']['2.3.7.6'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'CachedLogonsCount',
  'type' => :string,
  'data' => '4',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.7_L1_Ensure_Interactive_logon_Prompt_user_to_change_password_before_expiration_is_set_to_between_5_and_14_days:
default['security_options']['interactivelogon']['2.3.7.7'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'PasswordExpiryWarning',
  'type' => :dword,
  'data' => '7',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.8_L1_Ensure_Interactive_logon_Require_Domain_Controller_Authentication_to_unlock_workstation_is_set_to_Enabled_MS_only:
default['security_options']['interactivelogon']['2.3.7.8'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'ForceUnlockLogon',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.9_L1_Ensure_Interactive_logon_Smart_card_removal_behavior_is_set_to_Lock_Workstation_or_higher:
default['security_options']['interactivelogon']['2.3.7.9'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'reg_name' => 'ScRemoveOption',
  'type' => :string,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.1_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_always_is_set_to_Enabled:
default['security_options']['microsoftnetworkclient']['2.3.8.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
  'reg_name' => 'RequireSecuritySignature',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.2_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_if_server_agrees_is_set_to_Enabled:
default['security_options']['microsoftnetworkclient']['2.3.8.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
  'reg_name' => 'EnableSecuritySignature',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.3_L1_Ensure_Microsoft_network_client_Send_unencrypted_password_to_third-party_SMB_servers_is_set_to_Disabled:
default['security_options']['microsoftnetworkclient']['2.3.8.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
  'reg_name' => 'EnablePlainTextPassword',
  'type' => :dword,
  'data' => '0',
}

# # xccdf_org.cisecurity.benchmarks_rule_2.3.9.1_L1_Ensure_Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session_is_set_to_15_or_fewer_minutes_but_not_0:
default['security_options']['microsoftnetworkserver']['2.3.9.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'AutoDisconnect',
  'type' => :dword,
  'data' => '15',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.2_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_always_is_set_to_Enabled:
default['security_options']['microsoftnetworkserver']['2.3.9.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'RequireSecuritySignature',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.3_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_if_client_agrees_is_set_to_Enabled:
default['security_options']['microsoftnetworkserver']['2.3.9.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'EnableSecuritySignature',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.4_L1_Ensure_Microsoft_network_server_Disconnect_clients_when_logon_hours_expire_is_set_to_Enabled:
default['security_options']['microsoftnetworkserver']['2.3.9.4'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'enableforcedlogoff',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.5_L1_Ensure_Microsoft_network_server_Server_SPN_target_name_validation_level_is_set_to_Accept_if_provided_by_client_or_higher_MS_only:
default['security_options']['microsoftnetworkserver']['2.3.9.5'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'SMBServerNameHardeningLevel',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.2_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_is_set_to_Enabled_MS_only:
default['security_options']['networkaccess']['2.3.10.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'RestrictAnonymousSAM',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.3_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares_is_set_to_Enabled_MS_only:
default['security_options']['networkaccess']['2.3.10.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'RestrictAnonymous',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' (Automated)
default['security_options']['networkaccess']['2.3.10.4'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'DisableDomainCreds',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.5_L1_Ensure_Network_access_Let_Everyone_permissions_apply_to_anonymous_users_is_set_to_Disabled:
default['security_options']['networkaccess']['2.3.10.5'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'EveryoneIncludesAnonymous',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.6_L1_Configure_Network_access_Named_Pipes_that_can_be_accessed_anonymously:
# default['security_options']['networkaccess']['2.3.10.6'] = {
#   'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
#   'reg_name' => 'NullSessionPipes',
#   'type' => :multi_string,
#   'data' => %w(),
# }

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.9_L1_Ensure_Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares_is_set_to_Enabled:
default['security_options']['networkaccess']['2.3.10.9'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'RestrictNullSessAccess',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.10_L1_Ensure_Network_access_Shares_that_can_be_accessed_anonymously_is_set_to_None:
default['security_options']['networkaccess']['2.3.10.10'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
  'reg_name' => 'NullSessionShares',
  'type' => :multi_string,
  'data' => %w( ),
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.11_L1_Ensure_Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM_is_set_to_Administrators_Remote_Access_Allow_MS_only
default['security_options']['networkaccess']['2.3.10.10'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'restrictremotesam',
  'type' => :string,
  'data' => 'O:BAG:BAD:(A;;RC;;;BA)',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.13_L1_Ensure_Network_access_Sharing_and_security_model_for_local_accounts_is_set_to_Classic_-_local_users_authenticate_as_themselves:
default['security_options']['networkaccess']['2.3.10.11'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'ForceGuest',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.1_L1_Ensure_Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM_is_set_to_Enabled:
default['security_options']['networksecurity']['2.3.11.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'UseMachineId',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.2_L1_Ensure_Network_security_Allow_LocalSystem_NULL_session_fallback_is_set_to_Disabled:
default['security_options']['networksecurity']['2.3.11.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
  'reg_name' => 'AllowNullSessionFallback',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.3_L1_Ensure_Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities_is_set_to_Disabled:
default['security_options']['networksecurity']['2.3.11.3'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u',
  'reg_name' => 'AllowOnlineID',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.4_L1_Ensure_Network_security_Configure_encryption_types_allowed_for_Kerberos_is_set_to_AES128_HMAC_SHA1_AES256_HMAC_SHA1_Future_encryption_types:
default['security_options']['networksecurity']['2.3.11.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters',
  'reg_name' => 'SupportedEncryptionTypes',
  'type' => :dword,
  'data' => '2147483644',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.6_L1_Ensure_Network_security_Force_logoff_when_logon_hours_expire_is_set_to_Enabled:
default['security_options']['networksecurity']['2.3.11.5'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'NoLMHash',
  'type' => :dword,
  'data' => '1',
}

# Inspec Profile is blank
# # xccdf_org.cisecurity.benchmarks_rule_2.3.11.6_L1_Ensure_Network_security_Force_logoff_when_logon_hours_expire_is_set_to_Enabled:
# default['security_options']['networksecurity']['2.3.11.6'] = {
#   'reg_key' => '',
#   'reg_name' => '',
#   'type' => :dword,
#   'data' => '',
# }

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.7_L1_Ensure_Network_security_LAN_Manager_authentication_level_is_set_to_Send_NTLMv2_response_only._Refuse_LM__NTLM:
default['security_options']['networksecurity']['2.3.11.7'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'LmCompatibilityLevel',
  'type' => :dword,
  'data' => '5',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.8_L1_Ensure_Network_security_LDAP_client_signing_requirements_is_set_to_Negotiate_signing_or_higher:
default['security_options']['networksecurity']['2.3.11.8'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'reg_name' => 'LDAPClientIntegrity',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.9_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption:
default['security_options']['networksecurity']['2.3.11.9'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
  'reg_name' => 'NTLMMinClientSec',
  'type' => :dword,
  'data' => '537395200',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.10_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption:
default['security_options']['networksecurity']['2.3.11.10'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
  'reg_name' => 'NTLMMinServerSec',
  'type' => :dword,
  'data' => '537395200',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.13.1_L1_Ensure_Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on_is_set_to_Disabled:
default['security_options']['shutdown']['2.3.13.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'ShutdownWithoutLogon',
  'type' => :dword,
  'data' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.15.1_L1_Ensure_System_objects_Require_case_insensitivity_for_non-Windows_subsystems_is_set_to_Enabled:
default['security_options']['systemobjects']['2.3.15.1'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel',
  'reg_name' => 'ObCaseInsensitive',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.15.2_L1_Ensure_System_objects_Strengthen_default_permissions_of_internal_system_objects_e.g._Symbolic_Links_is_set_to_Enabled:
default['security_options']['systemobjects']['2.3.15.2'] = {
  'reg_key' => 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager',
  'reg_name' => 'ProtectionMode',
  'type' => :dword,
  'data' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.1_L1_Ensure_User_Account_Control_Admin_Approval_Mode_for_the_Built-in_Administrator_account_is_set_to_Enabled:
# As requested by GIS team: Rushikesh
default['security_options']['useraccountcontrol']['2.3.17.1'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'FilterAdministratorToken',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.2_L1_Ensure_User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop_is_set_to_Disabled:
default['security_options']['useraccountcontrol']['2.3.17.2'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'EnableUIADesktopToggle',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.3_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode_is_set_to_Prompt_for_consent_on_the_secure_desktop:
default['security_options']['useraccountcontrol']['2.3.17.3'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'ConsentPromptBehaviorAdmin',
  'type' => :dword,
  'data' => '2',
  'data_rollback' => '5',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.4_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users_is_set_to_Automatically_deny_elevation_requests:
default['security_options']['useraccountcontrol']['2.3.17.4'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'ConsentPromptBehaviorUser',
  'type' => :dword,
  'data' => '0',
  'data_rollback' => '1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.5_L1_Ensure_User_Account_Control_Detect_application_installations_and_prompt_for_elevation_is_set_to_Enabled:
default['security_options']['useraccountcontrol']['2.3.17.5'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'EnableInstallerDetection',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.6_L1_Ensure_User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations_is_set_to_Enabled:
default['security_options']['useraccountcontrol']['2.3.17.6'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'EnableSecureUIAPaths',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# Excluded/Reverted back - 01/09/2020 - due to potential impact on Network Mapping (SPN)
# # xccdf_org.cisecurity.benchmarks_rule_2.3.17.7_L1_Ensure_User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode_is_set_to_Enabled:
default['security_options']['useraccountcontrol']['2.3.17.7'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'EnableLUA',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.8_L1_Ensure_User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation_is_set_to_Enabled:
default['security_options']['useraccountcontrol']['2.3.17.8'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'PromptOnSecureDesktop',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.9_L1_Ensure_User_Account_Control_Virtualize_file_and_registry_write_failures_to_per-user_locations_is_set_to_Enabled:
default['security_options']['useraccountcontrol']['2.3.17.9'] = {
  'reg_key' => 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
  'reg_name' => 'EnableVirtualization',
  'type' => :dword,
  'data' => '1',
  'data_rollback' => '0',
}
