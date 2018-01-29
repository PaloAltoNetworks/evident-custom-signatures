#
# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
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

#
# Description:
# Ensure IAM Master and IAM Manager roles are active (CIS-01-18)
# 
# The current recommendation is to divide account and permission configuration permissions between 2 roles, which are:
# - IAM Master: creates users, groups and roles; assigns permissions to roles
# - IAM Manager: assigns users and roles to groups
# In this model, IAM Master and IAM Manager must work together in a 2-person rule manner, in order for a user to gain access to a permission.
#
# Default Conditions:
# - PASS: Both IAM Master and IAM Manager role exists, and have the appropriate permission
# - FAIL: if one of the following is true
#         - IAM master role doesn't exists or doesn't have the appropriate permission
#         - IAM Manager role doesn't exists or doens't have the appropriate permission
#         - IAM Manager and master role exists, but not active (no principal in assume role)
#         - IAM Manager and master role exists, but a user/group/role can assume both
#
# Resolution:
# See https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
# Section 1.18 for remediation steps
#


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # To save API call from inspecting every single role,
  # provide the IAM role name for both IAM master role and IAM Manager role
  # If one the role name is left blank, all role will be inspected.
  # WARNING: Inspecting all roles requires additional API calls (depending on the number of role in the account) 
  #          also increases the signature runtime
  #          DO NOT leave the role names empty if you have more than 30 IAM roles.
  master_role_name: 'cis_1_18_master',
  manager_role_name: 'cis_1_18_manager',

  # If set to true, the check ensure that MFA requirement is set in the policy for allowed actions
  # The check returns FAIL if require_mfa is set to true, but the role's policy document doesn't require MFA
  require_mfa: true,

  # If set to true, IAM role inspection result will be included in the alert
  # if you have a lot of roles, you should not enable this as it will exceed the maximum alert metadata limit
  debug_iam_roles: false,

  # Permission that master role should have.
  # The check will fail if there is missing or extra permissions
  # See https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
  # Section 1.18
  master_policy: {
    allow: [
      "iam:AttachRolePolicy",
      "iam:CreateGroup",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:CreateRole",
      "iam:CreateUser",
      "iam:DeleteGroup",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DeleteUser",
      "iam:PutRolePolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroups",
      "iam:ListGroupsForUser",
      "iam:ListPolicies",
      "iam:ListPoliciesGrantingServiceAccess",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListRoles",
      "iam:ListUsers"
      ],

    deny: [
      "iam:AddUserToGroup",
      "iam:AttachGroupPolicy",
      "iam:DeleteGroupPolicy",
      "iam:DeleteUserPolicy",
      "iam:DetachGroupPolicy",
      "iam:DetachRolePolicy",
      "iam:DetachUserPolicy",
      "iam:PutGroupPolicy",
      "iam:PutUserPolicy",
      "iam:RemoveUserFromGroup",
      "iam:UpdateGroup",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateUser",
    ]
  },
  

  # Permission that manager role should have.
  # The check will fail if there is missing or extra permissions
  # See https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
  # Section 1.18
  manager_policy: {
    allow: [
      "iam:AddUserToGroup",
      "iam:AttachGroupPolicy",
      "iam:DeleteGroupPolicy",
      "iam:DeleteUserPolicy",
      "iam:DetachGroupPolicy",
      "iam:DetachRolePolicy",
      "iam:DetachUserPolicy",
      "iam:PutGroupPolicy",
      "iam:PutUserPolicy",
      "iam:RemoveUserFromGroup",
      "iam:UpdateGroup",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateUser",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroups",
      "iam:ListGroupsForUser",
      "iam:ListPolicies",
      "iam:ListPoliciesGrantingServiceAccess",
      "iam:ListPolicyVersions",
      "iam:ListRolePolicies",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListRoles",
      "iam:ListUsers"
    ],
    deny: [
      "iam:CreateGroup",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:CreateRole",
      "iam:CreateUser",
      "iam:DeleteGroup",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DeleteUser",
      "iam:PutRolePolicy"
    ]
  }

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#
# deep inspection attribute will be included in each alert
configure do |c|
  # By default, a custom signature is executed against all region. 
  # In this case, we can query IAM from one of the region. 
  # So, let's restrict the region to just us-east-1
  c.valid_regions     = [:us_east_1]
  # override the region displayed in the alert from us-east-1 to global
  c.display_as        = :global
  c.deep_inspection   = [:options, :iam_roles]
end


################################################################################
#
# This is the entrypoint. Custom sig engine will execute 'perform'
#
################################################################################
def perform(aws)
  @results = {
    master_role_name: [],
    master_assume_principal: [],
    manager_role_name: [],
    manager_assume_principal: [],
    check_messages: []
  }

  @cached_iam_roles = {}
  @cached_managed_policies = {}

  # Populate policy documents
  aws.iam.list_roles.roles.each do |role|
    role_name = role.role_name
    assume_policy_doc = JSON.parse(URI.decode(role[:assume_role_policy_document])) if role[:assume_role_policy_document].is_a? String
    @cached_iam_roles[role_name] = {
      "assume_policy_doc" => assume_policy_doc
    }
  end

  # if IAm master or IAM manager role name is not given
  # scan through all IAM roles
  if @options[:master_role_name] == '' or @options[:manager_role_name] == ''
    @cached_iam_roles.keys.each do |role_name|
      evaluate_effective_role_permissions(aws, role_name)

      compliance_check('master', role_name)
      compliance_check('manager', role_name)
    end
  else
    evaluate_effective_role_permissions(aws, @options[:master_role_name])
    evaluate_effective_role_permissions(aws, @options[:manager_role_name])

    compliance_check('master',@options[:master_role_name])
    compliance_check('manager',@options[:manager_role_name])
  end


  if @options[:debug_iam_roles]
    set_data(options: @options, iam_roles: @cached_iam_roles) 
  else
    iam_roles_compressed = {}
    @cached_iam_roles.keys.each do | role_name |
      iam_roles_compressed[role_name] = { error: @cached_iam_roles[role_name]["Error"]}
    end
    set_data(options: @options, iam_roles: iam_roles_compressed )
  end

  # At this point, we should have identified if the account has IAM master & IAM manager roles.
  # Fail immediately if the account doesn't have both roles.
  if @results[:master_role_name].count < 1 or @results[:manager_role_name].count < 1 
    fail(message: "Missing IAM master role or IAM manager role", result: @results )
    return
  end

  # Master & manager exists. See if they're active.
  if @results[:master_assume_principal].count < 1 or @results[:manager_assume_principal].count < 1
    fail(message: "IAM master & manager role exists, but one or both are not active.", result: @results )
    return
  end

  # Per CIS 1.18, there should be a separation of duty. So, a user/group/role should not be able to assume both 
  if (@results[:master_assume_principal] & @results[:manager_assume_principal]).count > 0 
    fail(message: "One or more user/group/role can assume both Master and Manager role", result: @results )
  else 
    pass(message: "Found IAM master role and IAM manager role. Both are active, and no user/group/role can assume both roles", result: @results )
  end
end

######################################################
# Grab the policy document from the managed policy.
# and cache it to avoid making redundant API calls
######################################################
def get_managed_policy_doc(aws, policy_arn)
  return @cached_managed_policies[policy_arn] if @cached_managed_policies.key?(policy_arn)
  
  policy_doc = aws.iam.get_policy_version({
    policy_arn: policy_arn,
    version_id: aws.iam.get_policy(policy_arn: policy_arn)[:policy][:default_version_id]
    }).policy_version.document

  policy_doc = JSON.parse(URI.decode(policy_doc)) if policy_doc.is_a? String

  @cached_managed_policies[policy_arn] = policy_doc
  return policy_doc
end



#####################################################
## Combine permissions from multiple policy documens
#####################################################
def combine_policy_doc(role_perm, policy_doc)
  if policy_doc['Statement'].is_a? Hash
    role_perm = combine_policy_statement(role_perm, policy_doc['Statement'])
  else
    policy_doc['Statement'].each do | statement |
      role_perm = combine_policy_statement(role_perm, statement)
    end
  end

  return role_perm
end


##################################################################
## Combine permissions from multiple policy document's statement
## Only if the permission has resource: "*"
##################################################################
def combine_policy_statement(role_perm, statement)
  effect = statement["Effect"]

  if (statement["Resource"].is_a? String) and statement["Resource"] != "*"
    return role_perm
  elsif (statement["Resource"].is_a? Array) and (statement["Resource"].include?("*") == false)
    return role_perm
  end 

  require_mfa = statement.key?("Condition") and 
                statement["Condition"].key?("Bool") and 
                statement["Condition"]["Bool"].key?("aws:MultiFactorAuthPresent") and
                statement["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] == "true"


  if statement["Action"].is_a? String
    role_perm[effect][statement["Action"]] = {"require_mfa" => require_mfa }
    return role_perm
  end

  statement["Action"].each do | action |
    if role_perm[effect].key?(action)
      # Based on http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
      # If there are 2 policies attached,
      # - policy 1 allow
      # - policy 2 allow with MFA
      # Without MFA, policy 2 will result in Default deny, and the final result will be ALLOW
      role_perm[effect][action]["require_mfa"] = false if require_mfa == false
    else
      role_perm[effect][action] = {"require_mfa" => require_mfa }
    end
  end

  return role_perm
end


##########################################################################
## Get the effective role permission, and add it to @cached_iam_roles
##########################################################################
def evaluate_effective_role_permissions(aws, role_name)
  begin
    
    role_perm = {
      "Allow" => {},
      "Deny" => {},
      "Error" => nil
    }
    # Process managed policy attached to the roles
    # and consolidate them to 'role_perm'
    attached_role_policies = aws.iam.list_attached_role_policies(role_name: role_name)[:attached_policies]
    attached_role_policies.each do | managed_policy |
      policy_arn = managed_policy[:policy_arn]
      policy_doc = get_managed_policy_doc(aws, policy_arn)
      role_perm = combine_policy_doc(role_perm, policy_doc)
    end    

    ## Process inline policy attached to the roles
    # and consolidate them to 'role_perm'
    role_inline_policies = aws.iam.list_role_policies(role_name: role_name).policy_names
    role_inline_policies.each do | policy_name |
      policy_doc = aws.iam.get_role_policy(role_name: role_name, policy_name: policy_name).policy_document
      policy_doc = JSON.parse(URI.decode(policy_doc)) if policy_doc.is_a? String
      role_perm = combine_policy_doc(role_perm, policy_doc)
    end

    role_perm["allow_count"] = role_perm["Allow"].count
    role_perm["deny_count"] = role_perm["Deny"].count
    role_perm["assume_policy_doc"] = @cached_iam_roles[role_name]["assume_policy_doc"]




  rescue StandardError => e
    if e.message.include? "does not exist"
      role_perm["Error"] = "IAM check: #{role_name} does not exists"
    else
      role_perm["Error"] = e.message
    end
  end

   @cached_iam_roles[role_name] = role_perm
  
end

###########################################################################
## COMPLIANCE CHECK
###########################################################################
def compliance_check(type, role_name)
  # Check the Allowed policy first
  allow_match_count = 0
  @cached_iam_roles[role_name]["Allow"].each do | action, details |
    if @options["#{type}_policy".to_sym][:allow].include?(action)
      if @options[:require_mfa]
        allow_match_count += 1 if details["require_mfa"]
      else
        allow_match_count += 1
      end
    end
  end

  deny_match_count = 0
  @cached_iam_roles[role_name]["Deny"].each do | action, details |
    deny_match_count += 1 if @options["#{type}_policy".to_sym][:deny].include?(action)
  end

  @cached_iam_roles[role_name]["#{type}_allow_match_count"] = allow_match_count
  @cached_iam_roles[role_name]["#{type}_deny_match_count"] = deny_match_count

  if @options["#{type}_policy".to_sym][:allow].count == allow_match_count and 
     @options["#{type}_policy".to_sym][:allow].count == @cached_iam_roles[role_name]["Allow"].count and
     @options["#{type}_policy".to_sym][:deny].count == deny_match_count and
     @options["#{type}_policy".to_sym][:deny].count == @cached_iam_roles[role_name]["Deny"].count
  then
    @results["#{type}_role_name".to_sym].push(role_name)

    # Evaluate assume policy document, see which users can assume the role

    @cached_iam_roles[role_name]["assume_policy_doc"]["Statement"].each do | statement |
      next if statement["Effect"] == "Deny"

      if statement["Principal"]["AWS"].is_a? String
        @results["#{type}_assume_principal".to_sym].push(statement["Principal"]["AWS"])
      elsif statement["Principal"]["AWS"].is_a? Array
        statement["Principal"]["AWS"].each do | principal|
          @results["#{type}_assume_principal".to_sym].push(principal)
        end
      end
    end
     
  end
end