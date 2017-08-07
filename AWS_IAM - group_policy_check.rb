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
# Check for group IAM policy violation
#
# This custom signature scans group's permisison (inline and attached policy)
# against a set of blacklisted permission
# against the 'approved' list of groups 
# 
# Default Conditions:
# - PASS: No violation found on the group permission
# - PASS: IAM group is in the 'approved list' (skipped from the check)
# - FAIL: IAM group is not in the 'approved list' and violation found 
#
# Resolution/Remediation:
# - Remove the permission from IAM group
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # List of blacklisted actions 
  # If one or more blacklisted action is found and the group is not in the 'approved' list,
  # a FAIL alert will be generated
  # 
  # It does string matching. For example, if the blacklisted item has iam:* :
  # - it matches iam:*
  # - it does NOT match iam:Create*  (unless added to the blacklist)
  # - it does NOT match iam:CreateUser (unless added to the blacklist)
  # - and so on
  # 
  # Case sensitive
  blacklisted_actions: [
    "*",
    "iam:*",
    "ec2:*"
    ],


  # List of "Approved" IAM group names.
  # GROUP listed in this list will NOT be checked
  #  
  # case sensitive
  approved_list: [
    "adminGroup"
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
  c.deep_inspection   = [:blacklisted_actions, :approved_list, :arn, :create_date, :group_id, :group_name, :path, :offending_managed_policies, :offending_inline_policies]
end


def perform(aws)
  if @options[:blacklisted_actions].count < 1
    error(message: "Blacklisted_actions cannot be emty")
    return
  end

  @managed_policies = {}
  group_list = aws.iam.list_groups[:groups]

  group_list.each do | group |
    set_data(@options)
    set_data(group)
    group_name = group[:group_name]

    if @options[:approved_list].include?(group_name)
      pass(message: "group #{group_name} is in the approved list. Skipping check", resource_id: group_id)
      next
    end

    offending_managed_policies = get_offending_managed_policies(aws,group_name,'group')
    offending_inline_policies = get_offending_inline_policies(aws,group_name, 'group')

    set_data(offending_managed_policies: offending_managed_policies, offending_inline_policies: offending_inline_policies)

    if offending_managed_policies.count > 0 or offending_inline_policies.count > 0
      fail(message: "offending IAM permission found on group #{group_name}", resource_id: group_name)
    else
      pass(message: "No offending IAM permission found on group #{group_name}", resource_id: group_name)
    end

  end


end



##############################################################################
#
# Go through IAM group/user's --Managed/Attached-- policy
# returns the list of offending managed policies
# 
# Type is either 'user' or 'group'
#
##############################################################################
def get_offending_managed_policies(aws, iam_name, type)
  offending_managed_policies = []
  if type == 'user'
    policies = aws.iam.list_attached_user_policies(user_name: iam_name).attached_policies
  elsif type == 'group'
    policies = aws.iam.list_attached_group_policies(group_name: iam_name).attached_policies
  else
    return offending_managed_policies
  end
    
  policies.each do | policy |
    policy_name = policy[:policy_name]
    evaluate_managed_policy(aws,policy) 

    if @managed_policies[policy_name][:offending_statements].count > 0
      offending_managed_policies.push(@managed_policies[policy_name]) 
    end
  end

  return offending_managed_policies
end


##############################################################################
#
# Go through IAM group's inline policy
# 
#
##############################################################################
def get_offending_inline_policies(aws, iam_name, type)
  offending_inline_policies = []

  if type == 'user'
    policies = aws.iam.list_user_policies(user_name: iam_name).policy_names
  elsif type == 'group'
    policies = aws.iam.list_group_policies(group_name: iam_name).policy_names
  else
    return offending_inline_policies
  end      

  policies.each do | policy_name |
    if type == 'user'
      policy_doc = aws.iam.get_user_policy(user_name: iam_name, policy_name: policy_name)[:policy_document]
    elsif type == 'group'
      policy_doc = aws.iam.get_group_policy(group_name: iam_name, policy_name: policy_name)[:policy_document]
    else
      next
    end

    policy_doc = JSON.parse(URI.decode(policy_doc)) if policy_doc.is_a? String

    offending_statements = get_offending_statement(policy_doc)

    if offending_statements.count > 0
      offending_inline_policies.push({
          policy_name: policy_name,
          offending_statements: offending_statements,
          policy_doc: policy_doc
        })
    end
  end

  return offending_inline_policies
end


################################################################################
#
# Populate @managed_policies with attached managed policy from users & groups
# Also evaluate if attached policy has admin access or not
#
################################################################################
def evaluate_managed_policy(aws,attached_policy)
  # an IAM managed policy can be attached to multiple IAM users or groups
  # To save API calls, a list of all attached managed policy (@managed_policies) is populated
  if @managed_policies.has_key?(attached_policy[:policy_name])
    return
  else
    policy_arn = attached_policy[:policy_arn]
    policy_detail = aws.iam.get_policy(policy_arn: policy_arn).policy

    policy_doc = aws.iam.get_policy_version({
      policy_arn: policy_arn,
      version_id: policy_detail[:default_version_id]
      }).policy_version.document

    policy_doc = JSON.parse(URI.decode(policy_doc)) if policy_doc.is_a? String


    @managed_policies[attached_policy[:policy_name]] = {
      policy_name: attached_policy[:policy_name],
      policy_arn: policy_arn,
      update_date: policy_detail[:update_date],
      offending_statements: get_offending_statement(policy_doc),
      policy_doc: policy_doc
    }
  end
end



###################################################################################
#
# Get the offending statement based on the
# @options[:blacklisted_actions]
#
# Returns the list of policy statement that has one or more offending actions
#
####################################################################################
def get_offending_statement(policy_doc)
  offending_statements = []

  if policy_doc['Statement'].is_a? Hash  
    offending_statements.push(policy_doc['Statement']) if statement_has_offending_action?(policy_doc['Statement'])
  else
    policy_doc['Statement'].each do | statement |
      offending_statements.push(statement) if statement_has_offending_action?(statement)
    end
  end

  return offending_statements
end



###################################################################################
#
# Evaluate policy statement and see if there is ALLOW for offending actions
# listed in @options[:blacklisted_actions]
#
# Returns true/false
###################################################################################
def statement_has_offending_action?(statement)
  # Evaluate Effect
  if statement['Effect'] != 'Allow'
    return false
  end

  # Evaluate the target resource 
  has_blacklisted_resource = false
  if statement['Resource'].is_a? Array
    has_blacklisted_resource = true if statement['Resource'].include?("*")
  else
    has_blacklisted_resource = true if statement['Resource'] == "*"
  end

  # IAM Allow can have Action and NotAction
  has_blacklisted_action = false
  if statement.key?('Action')
    if statement['Action'].is_a? Array 
      has_blacklisted_action = true if (statement['Action'] & @options[:blacklisted_actions]).count > 0 
    else
      has_blacklisted_action = true if @options[:blacklisted_actions].include?(statement['Action'])
    end


  elsif statement.key?('NotAction')
    if statement['NotAction'].is_a? Array
      # if NotAction list does not contain all actions listed in blacklisted action
      # some of the blacklisted actions are allowed
      has_blacklisted_action = true if (statement['NotAction'] & @options[:blacklisted_actions]).count != @options[:blacklisted_actions].count
    else
      # because there is just one action in NotAction 
      has_blacklisted_action = true if @options[:blacklisted_actions]> 1
      has_blacklisted_action = true if (@options[:blacklisted_actions].include?(statement['NotAction']) == false)
    end

  end

  return false if has_blacklisted_action == false

  if has_blacklisted_resource
    return true
  else
    return false
  end

end