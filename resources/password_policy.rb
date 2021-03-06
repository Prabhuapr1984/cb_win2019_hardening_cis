resource_name :password_policy

property :policy_name, String, name_property: true
property :policy_command, String, required: true
property :value, Integer, required: true

action :set do
  execute new_resource.policy_name do
    command "net accounts /#{new_resource.policy_command}:#{new_resource.value}"
    action :run
    not_if { ::File.exist?("C:\\temp\\#{new_resource.policy_name}.lock") }
    notifies :create, "file[C:\\temp\\#{new_resource.policy_name}.lock]", :immediately
  end

  file "C:\\temp\\#{new_resource.policy_name}.lock" do
    action :create
  end
end
