#
# Copyright (c) 2013, 2014, 2015, 2016, 2017. Evident.io (Evident). All Rights Reserved. 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's customers; 
#   and (b) any works created by Evident.io prior to its commencement of any Services for Customer. 
#
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations of the Customer 
#   as they relate to the Evident.io platform and products, 
#   and always subject to Evident.io's underlying intellectual property rights.
#
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, 
#   EVEN IF EVIDENT.IO HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#  THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#  EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#

# Description:
# Check for role IAM policy violation
#
# This custom signature scans role's attached policies
# against a list of required policies
# 
# Default Conditions:
# - PASS: No violation found - all required polices are attached to the role
# - PASS: IAM role is in the 'approved list' (skipped from the check)
# - FAIL: IAM role is not in the 'approved list' and violation found 
#
# Resolution/Remediation:
# - Attach the required polies to the IAM role
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'    
# Configurable options                                                                  
@options = {  
  # List of required policies
  # If one or more of the required polices are not attached and the role is not in the 'approved list',
  # a FAIL alert will be generated
  # 
  # Case sensitive
  
  required_policies: [
    "POLICY_NAME_1",
    "POLICY_NAME_2"
  ],

  # List of 'approved' IAM role names.
  # ROLE listed in this list will NOT be checked
  #  
  # case sensitive
  approved_list: [
    "adminRole"
  ]
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
  # By default, a custom signature is executed against all region. 
  # In this case, we can query IAM from one of the region. 
  # So, let's restrict the region to just us-east-1
  c.valid_regions     = [:us_east_1]
  # override the region displayed in the alert from us-east-1 to global
  c.display_as        = :global
  c.deep_inspection   = [:required_policies, :approved_list, :arn, :create_date, :role_id, :role_name, :path, :attached_policies, :attached_required_policies]
end


def perform(aws)

  if @options[:required_policies].count < 1
    error(message: "Required_Policies cannot be empty")
    return
  end

  role_list = aws.iam.list_roles[:roles]

  role_list.each do | role |
    set_data(@options)
    set_data(role)
    role_name = role[:role_name]

    begin
      if @options[:approved_list].include?(role_name)
        pass(message: "role #{role_name} is in the approved list. Skipping check", resource_id: role_name)
        next
      end

      attached_policies = get_attached_policies(aws,role_name,'role')
      
      set_data(attached_policies: attached_policies)
      
      attached_required_policies = []
      @options[:required_policies].each do |value|
        if attached_policies.include? value
            attached_required_policies.push(value)
        end
      end

      set_data(attached_required_policies: attached_required_policies)

      if attached_required_policies.count != @options[:required_policies].count
        fail(message: "Required Policy missing on role #{role_name}", resource_id: role_name)
      else
        pass(message: "All Required Policies found on role #{role_name}", resource_id: role_name)
      end
    rescue StandardError => e
        fail(message: "ERROR in processing role #{role_name}", resource_id: role_name, error: e.message)
    end
  end
end

##############################################################################
#
# Go through IAM group/user/role's --Managed/Attached-- policy
# returns the list of offending managed policies
# 
# Type is either 'group', 'user', or 'role'
#
##############################################################################

def get_attached_policies(aws, iam_name, type)
  attached_policies = []
  if type == 'user'
    policies = aws.iam.list_attached_user_policies(user_name: iam_name).attached_policies
  elsif type == 'group'
    policies = aws.iam.list_attached_group_policies(group_name: iam_name).attached_policies
  elsif type == 'role'
    policies = aws.iam.list_attached_role_policies(role_name: iam_name).attached_policies
  else
    return attached_policies
  end

  policies.each do | policy |
    attached_policies.push(policy[:policy_name])
  end

  return attached_policies
end