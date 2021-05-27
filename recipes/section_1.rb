# Cookbook:: cb_win2019_hardening_cis
# Recipe:: section_1
#
# Copyright:: 2020, The Authors, All Rights Reserved.

return unless node['kernel']['cs_info']['domain'] == 'WORKGROUP'

# xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords:
password_policy 'password_history' do
  policy_command 'uniquepw'
  value 24
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.2_L1_Ensure_Maximum_password_age_is_set_to_60_or_fewer_days_but_not_0:
password_policy 'password_age' do
  policy_command 'maxpwage'
  value 30
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.3_L1_Ensure_Minimum_password_age_is_set_to_1_or_more_days:
password_policy 'password_age' do
  policy_command 'minpwage'
  value 1
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.4_L1_Ensure_Minimum_password_length_is_set_to_14_or_more_characters:
password_policy 'password_length' do
  policy_command 'minpwlen'
  value 14
  action :set
end
