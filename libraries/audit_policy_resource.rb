require 'chef/resource'

class Chef
  class Resource
    class AuditPolicy < Chef::Resource
      resource_name :audit_policy
      provides :audit_policy

      property :name, String, default: ''
      property :category, String, default: ''
      property :subcategory, String, default: ''
      property :flag, String, default: ''

      allowed_actions :set
      default_action :set
    end
  end
end
