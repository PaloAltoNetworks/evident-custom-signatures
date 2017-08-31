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
# Check for Glacier vault policy 
# This signature check the Glacier vault's policy against 'blacklisted_actions' and 'whitelisted_accounts'
# In addition, this signature also check if Glacier policy allows "*" action or if it is exposed publicly
# 
# Default Conditions:
# - PASS: No offending policy or the vault is not exposed publicly
# - FAIL: One or more offending policy found in the vault's policy
#
# Resolution/Remediation:
# - Change/remove the offending policy
#


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options    
@options = {
  # List of blacklisted actions that should not be allowed.
  # CASE SENSITIVE
  #
  # The actions will be matched literally. For example,
  # if you list glacier:Put* , 
  # - it will     catch glacier:Put*     action in the policy statement
  # - it will NOT catch glacier:PutImage action in the policy statement
  #
  # In addition to checking the 'blacklisted_actions',
  # this signature also checks for "*" in the actions:
  # - "Actions" : "*"
  # - "Actions" : ["*"]
  # - "Actions" : ["glacier:<action>", "*"]
  #
  # If you use "NotAction" instead of "Action" in the policy,
  # FAIL alert may still be triggered if a certain blacklisted_actions is allowed
  # (for a PASS alert, all blacklisted_actions will need to be listed in NotAction policy statement)
  # 
  blacklisted_actions: [
    "glacier:*",
    "glacier:Delete*",
    "glacier:Set*",
    "glacier:Get*",
    "glacier:Remove*",
    "glacier:Describe*",
    "glacier:List*",
    "glacier:AbortMultipartUpload",
    "glacier:AbortVaultLock",
    "glacier:AddTagsToVault",
    "glacier:CompleteMultipartUpload",
    "glacier:CompleteVaultLock",
    "glacier:CreateVault",
    "glacier:DeleteArchive",
    "glacier:DeleteVault",
    "glacier:DeleteVaultAccessPolicy",
    "glacier:DeleteVaultNotifications",
    "glacier:DescribeJob",
    "glacier:DescribeVault",
    "glacier:GetDataRetrievalPolicy",
    "glacier:GetJobOutput",
    "glacier:GetVaultAccessPolicy",
    "glacier:GetVaultLock",
    "glacier:GetVaultNotifications",
    "glacier:InitiateJob",
    "glacier:InitiateMultipartUpload",
    "glacier:InitiateVaultLock",
    "glacier:ListJobs",
    "glacier:ListMultipartUploads",
    "glacier:ListParts",
    "glacier:ListProvisionedCapacity",
    "glacier:ListTagsForVault",
    "glacier:ListVaults",
    "glacier:PurchaseProvisionedCapacity",
    "glacier:RemoveTagsFromVault",
    "glacier:SetDataRetrievalPolicy",
    "glacier:SetVaultAccessPolicy",
    "glacier:SetVaultNotifications",
    "glacier:UploadArchive",
    "glacier:UploadMultipartPart",
  ],

  # List the whitelisted aws accounts here. Example:
  #  
  #   whitelisted_aws_accounts: [
  #     "1234568910"
  #   ],
  #
  # If the whitelist is not empty, FAIL alert may be triggered 
  # if this signature finds non-whitelisted AWS accounts.
  # (By default, this signature whitelist AWS account that host the resource
  # 
  # In addition, FAIL alert may also be generated if "*" is find on the principal:
  # - ["Principal"] : "*"
  # - ["Principal"]["AWS"] : "*"
  # - ["Principal"]["AWS"] : ["*"]
  # - ["Principal"]["AWS"] : [<other_accounts>,"*"]
  # (it is possible to set the policy in above format through CLI)
  whitelisted_aws_accounts: [
  ],


  # There are too many possible combination for evaluating the condition
  # http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
  # 
  # To simplify, list the conditions that you use to restrict the access.
  # If the statement in the policy doc isn't one of the condition listed in this parameter,
  # a FAIL alert may be generated instead of PASS
  #
  # Example:
  #   restricting_conditions: [
  #     {condition_type: "StringEquals", condition_key: "aws:sourceVpce"}
  #   ]
  restricting_conditions: [

  ],

  # Set the maximum number of records retrieved per API call
  # Valid option: integer (range not specified in API doc)
  max_results: 100

}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:vault_name, :vault_arn, :creation_date, :offending_statements, :policy_doc, :options]
end


def perform(aws)
  begin
    @self_account_number = nil
    resp = aws.glacier.list_vaults(limit: @options[:max_results])
    finished = false  
  rescue StandardError => e
    if e.message.include?("NoMethodError")
      error(message: "Error in getting the Glacier vault list. Please check the ESP permission")
    else
      error(message: e.message)
    end
    return
  end
  
  while finished == false
    resp[:vault_list].each do | resource |
      check_resource(resource,aws)
    end

    if resp[:marker].nil? or resp[:marker] == ''
      finished = true
    else
      resp = aws.glacier.list_vaults(marker: resp[:marker], limit: @options[:max_results])
    end
  end

end


def check_resource(resource,aws)
  begin
    resource_name = resource[:vault_name]
    
    # get the account number from vault's arn
    match_data = resource[:vault_arn].match(/arn:aws:glacier:[^:]+:(?<account_number>\d+):/)
    @self_account_number = match_data["account_number"]

    policy_doc = aws.glacier.get_vault_access_policy({vault_name: resource_name, account_id: @self_account_number})[:policy][:policy]
    if policy_doc.is_a? String
      policy_doc = JSON.parse(policy_doc)
    end
    
    offending_statements = get_offending_statement(policy_doc)

    set_data(resource)
    set_data(offending_statements: offending_statements, policy_doc: policy_doc, options: @options)
    if offending_statements.count > 0
      fail(message: "Vault #{resource_name} one or more has offending policy statements", resource_id: resource_name)
    else
      pass(message: "Vault #{resource_name} does not have offending policy statement nor exposed publicly", resource_id: resource_name)
    end

  rescue StandardError => e
    if e.message.include?("No vault access policy is set for")
      pass(message: "Vault #{resource_name} does not have any policy set", resource_id: resource_name)
    else
      error(message: "Error in processing vault #{resource_name}. Error: #{e.message}", resource_id: resource_name)
    end

    return
  end
end


###################################################################################
#
# Get the list of the offending statements
# Each statement is passed to `statement_has_offending_action` to be checked
#
###################################################################################
def get_offending_statement(policy_doc)
  offending_statements = []

  begin
    if policy_doc['Statement'].is_a? Hash  
      offending_statements.push(policy_doc['Statement']) if statement_has_offending_action?(policy_doc['Statement'])
    else
      policy_doc['Statement'].each do | statement |
        offending_statements.push(statement) if statement_has_offending_action?(statement)
      end
    end    
  rescue StandardError => e
    offending_statements.push("ERROR in processing the policy doc: #{e.message}")
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

  # IAM Allow can have Action and NotAction
  has_blacklisted_action = false
  if statement.key?('Action')
    if statement['Action'].is_a? Array 
      has_blacklisted_action = true if (statement['Action'] & @options[:blacklisted_actions]).count > 0 
      has_blacklisted_action = true if statement['Action'].include?("*")
    else
      has_blacklisted_action = true if @options[:blacklisted_actions].include?(statement['Action'])
      has_blacklisted_action = true if statement['Action'] == "*"
    end


  elsif statement.key?('NotAction')
    if statement['NotAction'].is_a? Array
      # if NotAction list does not contain all actions listed in blacklisted action
      # some of the blacklisted actions are allowed
      has_blacklisted_action = true if (statement['NotAction'] & @options[:blacklisted_actions]).count != @options[:blacklisted_actions].count
      has_blacklisted_action = false if statement['NotAction'].include?("*")
    else
      if statement['NotAction'] != "*"
        # because there is just one action in NotAction
        has_blacklisted_action = true if @options[:blacklisted_actions].count > 1
        has_blacklisted_action = true if (@options[:blacklisted_actions].include?(statement['NotAction']) == false)
      end
    end

  end

  # Check the principals
  other_principals_found = false
  if statement["Principal"].is_a? Hash
    # For simplicity, only AWS principals are checked. Service or CannonicalUser are excluded
    if statement["Principal"].key?("AWS")
      if statement["Principal"]["AWS"].is_a? Array
        other_principals_found = true if statement["Principal"]["AWS"].include?("*") 

        if @options[:whitelisted_aws_accounts].count > 0
          statement["Principal"]["AWS"].each do | principal |
            other_principals_found = true if aws_principal_whitelisted?(principal) == false
          end
        end
      else
        if statement["Principal"]["AWS"] == "*"
          other_principals_found = true
        else
          if aws_principal_whitelisted?(statement["Principal"]["AWS"]) == false and @options[:whitelisted_aws_accounts].count > 0
            other_principals_found = true 
          end
        end
      end
    end
  else
    other_principals_found = true if statement["Principal"] == "*"
  end

  # If there's no blacklisted action, return false to indicate no offending statement
  return false if has_blacklisted_action == false

  if other_principals_found
    # Before we send true to indicate offending statement, let's check the condition
    if statement.key?("Condition")
      if statement_restricted_by_condition?(statement["Condition"])
        return false 
      else
        return true
      end
    else
      # since there is no condtition, return true to indicate offending statement
      return true
    end
  else
    return false
  end

end

#####################################################################################
#
# AWS Principal check
# AWS principal should look like: arn:aws:iam::<account_number>:<root/role/user>
#
# The principal is NOT considered as whitelisted if one of the following is true:
# - principal is "*"
# - principal doesn't follow naming convention
# - the account number isn't whitelisted.
# 
#####################################################################################
def aws_principal_whitelisted?(principal)
  return false if principal == "*"

  principal_account_number = nil

  ## See if the principal matches 12 digit account number
  ## AWS sometimes convert the account number to ARN format if the policy is modified
  ## through AWS console
  if principal.match(/\d{12}/)
    principal_account_number = principal
  else
    ## Principal can also be defined in ARN format.
    match_data = principal.match(/arn:aws:iam::(?<account_number>\d+)/)

    ## This should not happen, if the principal does not follow aws naming convention, 
    ## the principal is assumed to be not whitelisted
    return false if match_data.nil?
    
    principal_account_number = match_data["account_number"]
  end

  # Self whitelisting (the account where the resource resides is whitelisted)
  return true if principal_account_number == @self_account_number

  if @options[:whitelisted_aws_accounts].include?(principal_account_number)
    return true
  else
    return false
  end
end

#####################################################################################
#
# Condition Checker
# This assume that @options[:restricting_conditions] has the list of conditions
# that makes a statement restricted.
#
#####################################################################################
def statement_restricted_by_condition?(condition)
  # If no condition is specified in @options[:restricting_conditions], return false immediately
  return false if @options[:restricting_conditions].count < 1

  # See if the condition statement has any of the restricting condition listed in  @options[:restricting_conditions]
  @options[:restricting_conditions].each do | restricting_condition |
    if condition.key?(restricting_condition[:condition_type])
      return true if condition[restricting_condition[:condition_type]].key?(restricting_condition[:condition_key])
    end
  end


  return false
end




