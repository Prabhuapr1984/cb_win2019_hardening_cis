# Cookbook:: cb_win2019_hardening_cis
# Recipe:: section_2
#
# Copyright:: 2020, The Authors, All Rights Reserved.

template 'c:/temp/secpol_workgroup.inf' do
  source 'secpol_workgroup.inf.erb'
  action :create
  not_if { node['kernel']['cs_info']['part_of_domain'] }
end

template 'c:/temp/secpol_domain.inf' do
  source 'secpol_domain.inf.erb'
  action :create
  only_if { node['kernel']['cs_info']['part_of_domain'] }
end

execute 'Backup_secpol_Pre_cis_Harden' do
  command ' secedit.exe /export /cfg %SystemRoot%\security\database\Backup_pre_cis_harden.inf '
  not_if { ::File.exists?("c:\\windows\\security\\database\\Backup_pre_cis_harden.inf") }
end

execute 'Apply_secpol_workgroup' do
  command ' cmd /c Secedit /configure /db C:\Windows\security\database\secpol_workgroup.sdb /cfg C:\temp\secpol_workgroup.inf /log C:\Windows\security\logs\secpol_workgroup.log '
  not_if { node['kernel']['cs_info']['part_of_domain'] }
end

execute 'Apply_secpol_Domain' do
  command ' cmd /c Secedit /configure /db C:\Windows\security\database\secpol_domain.sdb /cfg C:\temp\secpol_domain.inf /log C:\Windows\security\logs\secpol_domain.log '
  only_if { node['kernel']['cs_info']['part_of_domain'] }
end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.44_WEB_Server
# cb_win2019_hardening_cis_user_privilege('Administrators') do
#   privilege %w(SeAssignPrimaryTokenPrivilege)
#   only_if { ::Win32::Service.exists?("W3SVC") }
# end

# Deploying - Section_2_3 Configurations
node['security_options']['accounts'].each do |config, reg|
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

node['security_options']['audit'].each do |config, reg|
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

node['security_options']['devices'].each do |config, reg|
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

node['security_options']['domainmember'].each do |config, reg|
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

node['security_options']['interactivelogon'].each do |config, reg|
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

node['security_options']['microsoftnetworkclient'].each do |config, reg|
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

node['security_options']['microsoftnetworkserver'].each do |config, reg|
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

node['security_options']['networkaccess'].each do |config, reg|
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

node['security_options']['networksecurity'].each do |config, reg|
  registry_key config do
    values [{
      name: reg['reg_name'],
      type: reg['type'],
      data: reg['data'] }]
    key reg['reg_key']
    recursive true
    action :create
    not_if { File.read('C:\\chef\\cache\\audit.json').include?(config.to_s) }
  end
end

node['security_options']['shutdown'].each do |config, reg|
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

node['security_options']['systemobjects'].each do |config, reg|
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

node['security_options']['useraccountcontrol'].each do |config, reg|
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

execute 'registry_key[2.3.10.6]' do
  command 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /f'
  not_if "reg query 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' /v NullSessionPipes"
end
