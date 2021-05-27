# Cookbook:: cb_win2019_hardening_cis
# Recipe:: section_18
#
# Copyright:: 2020, The Authors, All Rights Reserved.

require 'json'

# xccdf_org.cisecurity.benchmarks_rule_18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed_MS_only
windows_package 'LAPS_AdmPwd_GPO_Extension' do
  # action :install
  source 'C:\\temp\\LAPS.x64.msi'
# source 'https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi'
  # installer_type :custom
  # options '/quiet'
end

# Deploy section_18 with exception aware
node['security_options']['personalization'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'],
      data: reg['data'] }]
    key reg['reg_key']
    action :create
    recursive true
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

node['security_options']['uac'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'],
      data: reg['data'] }]
    key reg['reg_key']
    action :create
    recursive true
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

node['security_options']['smb'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'],
      data: reg['data'] }]
    key reg['reg_key']
    action :create
    recursive true
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

node['security_options']['others'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'],
      data: reg['data'] }]
    key reg['reg_key']
    action :create
    recursive true
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

node['security_options']['mss'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'],
      data: reg['data'] }]
    key reg['reg_key']
    action :create
    recursive true
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

node['security_options']['remove'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'] }]
      # data: reg['data'] }]
    key reg['reg_key']
    action :delete
    recursive true
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

execute 'registry_key[18.5.14.1]' do
  command 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v \\\*\\SYSVOL /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f'
  not_if { registry_data_exists?('HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths', { name: '\\\*\\SYSVOL', type: :string, data: 'RequireMutualAuthentication=1, RequireIntegrity=1' }, :x86_64) }
end
