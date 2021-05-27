#
# Cookbook:: cb_win2019_hardening_cis
# Recipe:: default
#
# Copyright:: 2021, The Authors, All Rights Reserved.

# Required if you are using continuous hardening using data_bag based exceptions
file 'C:\\chef\\cache\\audit.json' do
  content "{ }"
  not_if { ::File.exist? ('C:\\chef\\cache\\audit.json') }
end

if platform_family?('windows')

  nt_version = node['platform_version'][0..15]

  if nt_version == '10.0.17763' # || (nt_version == '6.0') "platform_version" : "6.3.9600"

    include_recipe "#{cookbook_name}::section_1"
    include_recipe "#{cookbook_name}::section_2"
    # include_recipe "#{cookbook_name}::section_9"
    include_recipe "#{cookbook_name}::section_17"
    include_recipe "#{cookbook_name}::section_18"

  else
    Chef::Log.warn("Only Windows '10.0.17763' is supported")
  end
else
  Chef::Log.warn('The Windows 2019 is only supported for CIS hardening and continuous hardening')
end
