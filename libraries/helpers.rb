require 'win32ole'

module Windows2012r2Hardening
  module Helpers
    def builtin_groups
      # "builtin_groups = [ \"Administrators\", \"Authenticated Users\", \"Guests\", \"LOCAL SERVICE\", \"NETWORK SERVICE\", \"NETWORK\", \"SERVICE\" ]"
      "builtin_groups = ['Administrators', 'Authenticated Users', 'Guests', 'LOCAL SERVICE', 'NETWORK SERVICE', 'NETWORK', 'SERVICE']"
    end

    def valid_users_groups(users_groups)
      wmi = ::WIN32OLE.connect('winmgmts://')
      validated_list = []
      users_groups.each do |user_group|
        if builtin_groups.include?(user_group)
          validated_list << user_group
        else
          wmi_query_users = 'select * from Win32_UserAccount where name=' + "'#{user_group}'"
          search_user = wmi.ExecQuery(wmi_query_users)
          wmi_query_groups = 'select * from Win32_Group where name=' + "'#{user_group}'"
          search_group = wmi.ExecQuery(wmi_query_groups)
          validated_list << user_group if search_user.each.count == 1 || search_group.each.count == 1
        end
      end

      return [''] if validated_list.empty?
      validated_list
    end
  end
end

Chef::Resource.send(:include, Windows2012r2Hardening::Helpers)
