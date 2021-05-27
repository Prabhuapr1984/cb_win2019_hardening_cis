require 'chef/provider'
require 'mixlib/shellout'

class Chef
  class Provider
    class AuditPolicy < Chef::Provider
      provides :audit_policy, platform_family: 'windows'

      def load_current_resource
        if new_resource.category != '' && new_resource.subcategory != ''
          raise "Only one of 'category' or 'subcategory' should be specified"
        end

        if new_resource.category != '' && !category_valid?
          raise "Invalid value '#{new_resource.category}' for category."
        end

        if new_resource.subcategory != '' && !subcategory_valid?
          raise "Invalid value '#{new_resource.subcategory}' for subcategory."
        end
      end

      action :set do
        unless policy_upto_date?
          converge_by 'Update the audit policy' do
            update_audit_policy
          end
        end
      end

      private

      def policy_upto_date?
        if new_resource.category != ''
          cat_get = execute_command("AuditPol /get /category:\"#{new_resource.category}\" /r").split("\r\r\n")
          cat_get = cat_get.drop(1)
          status = cat_get.map { |s| s.split(',')[4].strip }
          # return true if (status.uniq.length == 1 && status.uniq[0] == new_resource.flag)
          return true if status.uniq.length == 1 && status.uniq[0] == new_resource.flag
        elsif new_resource.subcategory != ''
          subcat_get = execute_command("AuditPol /get /subcategory:\"#{new_resource.subcategory}\" /r").split("\r\r\n")
          subcat_get = subcat_get.drop(1)
          status = subcat_get.map { |s| s.split(',')[4].strip }
          # return true if (status.uniq.length == 1 && status.uniq[0] == new_resource.flag)
          return true if status.uniq.length == 1 && status.uniq[0] == new_resource.flag
        end
      end

      def category_valid?
        return true if valid_category_list.include?(new_resource.category)
      end

      def subcategory_valid?
        return true if valid_subcategory_list.include?(new_resource.subcategory)
      end

      def valid_category_list
        cat = execute_command('AuditPol /list /category /r').split("\r\n")
        cat.delete('Category/Subcategory,GUID')
        cat.map { |d| d.split(',')[0].strip }
      end

      def valid_subcategory_list
        subcat = execute_command('AuditPol /list /subcategory:* /r').split("\r\n")
        subcat.delete('Category/Subcategory,GUID')
        subcategories = subcat.map { |d| d.split(',')[0].strip }
        categories = valid_category_list
        subcategories.reject { |s| categories.include? s }
      end

      def update_audit_policy
        cmdline_flag = ''
        if new_resource.flag == 'No Auditing'
          cmdline_flag = '/success:disable /failure:disable'
        elsif new_resource.flag == 'Success and Failure'
          cmdline_flag = '/success:enable /failure:enable'
        elsif new_resource.flag == 'Success'
          cmdline_flag = '/success:enable /failure:disable'
        elsif new_resource.flag == 'Faliure'
          cmdline_flag = '/success:disable /failure:enable'
        end

        if new_resource.category != ''
          execute_command("AuditPol /set /category:\"#{new_resource.category}\" #{cmdline_flag}")
        elsif new_resource.subcategory != ''
          execute_command("AuditPol /set /subcategory:\"#{new_resource.subcategory}\" #{cmdline_flag}")
        end
      end

      def execute_command(command)
        cmd = Mixlib::ShellOut.new(command)
        cmd.run_command
        raise "Execution of command '#{command}' failed with error\n\n#{cmd.error!}\n\n" if cmd.error?
        cmd.stdout
      end
    end
  end
end
