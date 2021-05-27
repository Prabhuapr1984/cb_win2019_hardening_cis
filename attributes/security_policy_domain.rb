# xccdf_org.cisecurity.benchmarks_rule_2.2.1_L1_Ensure_Access_Credential_Manager_as_a_trusted_caller_is_set_to_No_One:
default['security_policy']['rights']['domain']['2.2.1'] = {
  'CIS_Control' => 'SeTrustedCredManAccessPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.2_L1_Configure_Access_this_computer_from_the_network:
default['security_policy']['rights']['domain']['2.2.2'] = {
  'CIS_Control' => 'SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.3_L1_Ensure_Act_as_part_of_the_operating_system_is_set_to_No_One:
default['security_policy']['rights']['domain']['2.2.3'] = {
  'CIS_Control' => 'SeTcbPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.5_L1_Ensure_Adjust_memory_quotas_for_a_process_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE:
default['security_policy']['rights']['domain']['2.2.5'] = {
  'CIS_Control' => 'SeIncreaseQuotaPrivilege = *S-1-5-20,*S-1-5-19,*S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.6_L1_Ensure_Allow_log_on_locally_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.6'] = {
  'CIS_Control' => 'SeInteractiveLogonRight = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Configure_Allow_log_on_through_Remote_Desktop_Services:
default['security_policy']['rights']['domain']['2.2.7'] = {
  'CIS_Control' => 'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.8_L1_Ensure_Back_up_files_and_directories_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.8'] = {
  'CIS_Control' => 'SeBackupPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.9_L1_Ensure_Change_the_system_time_is_set_to_Administrators_LOCAL_SERVICE:
default['security_policy']['rights']['domain']['2.2.9'] = {
  'CIS_Control' => 'SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.10_L1_Ensure_Change_the_time_zone_is_set_to_Administrators_LOCAL_SERVICE:
default['security_policy']['rights']['domain']['2.2.10'] = {
  'CIS_Control' => 'SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.11_L1_Ensure_Create_a_pagefile_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.11'] = {
  'CIS_Control' => 'SeCreatePagefilePrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.12_L1_Ensure_Create_a_token_object_is_set_to_No_One:
default['security_policy']['rights']['domain']['2.2.12'] = {
  'CIS_Control' => 'SeCreateTokenPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.13_L1_Ensure_Create_global_objects_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE:
default['security_policy']['rights']['domain']['2.2.13'] = {
  'CIS_Control' => 'SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.14_L1_Ensure_Create_permanent_shared_objects_is_set_to_No_One:
default['security_policy']['rights']['domain']['2.2.14'] = {
  'CIS_Control' => 'SeCreatePermanentPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.15_L1_Configure_Create_symbolic_links:
default['security_policy']['rights']['domain']['2.2.15'] = {
  'CIS_Control' => 'SeCreateSymbolicLinkPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.16_L1_Ensure_Debug_programs_is_set_to_NONE:
default['security_policy']['rights']['domain']['2.2.16'] = {
  'CIS_Control' => 'SeDebugPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.17_L1_Configure_Deny_access_to_this_computer_from_the_network:
default['security_policy']['rights']['domain']['2.2.17'] = {
  'CIS_Control' => 'SeDenyNetworkLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.18_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests:
default['security_policy']['rights']['domain']['2.2.18'] = {
  'CIS_Control' => 'SeDenyBatchLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.19_L1_Ensure_Deny_log_on_as_a_service_to_include_Guests:
default['security_policy']['rights']['domain']['2.2.19'] = {
  'CIS_Control' => 'SeDenyServiceLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.20_L1_Ensure_Deny_log_on_locally_to_include_Guests:
default['security_policy']['rights']['domain']['2.2.20'] = {
  'CIS_Control' => 'SeDenyInteractiveLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Configure_Deny_log_on_through_Remote_Desktop_Services:
default['security_policy']['rights']['domain']['2.2.21'] = {
  'CIS_Control' => 'SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Configure_Enable_computer_and_user_accounts_to_be_trusted_for_delegation:
default['security_policy']['rights']['domain']['2.2.22'] = {
  'CIS_Control' => 'SeEnableDelegationPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.23_L1_Ensure_Force_shutdown_from_a_remote_system_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.23'] = {
  'CIS_Control' => 'SeRemoteShutdownPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.24_L1_Ensure_Generate_security_audits_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE:
default['security_policy']['rights']['domain']['2.2.24'] = {
  'CIS_Control' => 'SeAuditPrivilege = *S-1-5-20,*S-1-5-19',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.25_L1_Configure_Impersonate_a_client_after_authentication:
default['security_policy']['rights']['domain']['2.2.25'] = {
  'CIS_Control' => 'SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6,*S-1-5-32-568',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Increase_scheduling_priority_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.26'] = {
  'CIS_Control' => 'SeIncreaseBasePriorityPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.27_L1_Ensure_Load_and_unload_device_drivers_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.27'] = {
  'CIS_Control' => 'SeLoadDriverPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.28_L1_Ensure_Lock_pages_in_memory_is_set_to_No_One:
default['security_policy']['rights']['domain']['2.2.28'] = {
  'CIS_Control' => 'SeLockMemoryPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.30_L1_Configure_Manage_auditing_and_security_log
default['security_policy']['rights']['domain']['2.2.30'] = {
  'CIS_Control' => 'SeSecurityPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.31_L1_Ensure_Modify_an_object_label_is_set_to_No_One:
default['security_policy']['rights']['domain']['2.2.31'] = {
  'CIS_Control' => 'SeRelabelPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.32_L1_Ensure_Modify_firmware_environment_values_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.32'] = {
  'CIS_Control' => 'SeSystemEnvironmentPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.33_L1_Ensure_Perform_volume_maintenance_tasks_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.33'] = {
  'CIS_Control' => 'SeManageVolumePrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.34_L1_Ensure_Profile_single_process_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.34'] = {
  'CIS_Control' => 'SeProfileSingleProcessPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.35_L1_Ensure_Profile_system_performance_is_set_to_Administrators_NT_SERVICEWdiServiceHost:
default['security_policy']['rights']['domain']['2.2.35'] = {
  'CIS_Control' => 'SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.36_L1_Ensure_Replace_a_process_level_token_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE:
default['security_policy']['rights']['domain']['2.2.36'] = {
  'CIS_Control' => 'SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.37_L1_Ensure_Restore_files_and_directories_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.37'] = {
  'CIS_Control' => 'SeRestorePrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.40_L1_Ensure_Take_ownership_of_files_or_other_objects_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.40'] = {
  'CIS_Control' => 'SeTakeOwnershipPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.46_L1_Ensure_Shut_down_the_system_is_set_to_Administrators:
default['security_policy']['rights']['domain']['2.2.46'] = {
  'CIS_Control' => 'SeShutdownPrivilege = *S-1-5-32-544',
}
