# Cookbook:: cb_win2019_hardening_cis
# Recipe:: section_9
#
# Copyright:: 2020, The Authors, All Rights Reserved.

# Deploying - Section_9 Configurations
node['windows_config']['firewall'].each do |config, reg|
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
