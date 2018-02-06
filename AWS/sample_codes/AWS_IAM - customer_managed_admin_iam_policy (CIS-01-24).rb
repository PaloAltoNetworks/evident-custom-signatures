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
# Ensure no customer managed IAM policy that allows full admin privilege (CIS-01-24)
#
# IAM policies are the means by which privileges are granted to users, groups, or roles. It is
# recommended and considered a standard security advice to grant the least privilege—that is,
# granting only the permissions required to perform a task.
#
#
# Default Conditions:
# - PASS: IAM policy does not have full admin (*:*) access
# - WARN: IAM policy has full admin access, but has no attachment
# - FAIL: IAM policy has full admin access and attached to user/group/role
#
# Resolution/Remediation:
# Customer created IAM policies that have a statement with
#   "Effect": "Allow" with 
#   "Action": "" over 
#   "Resource": "" 
# should be removed.
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # WARN instead of FAIL if the policy is not attached to user/group/role
  warn_if_not_attached: true
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
  c.deep_inspection   = [:policy_name,:arn,:attachment_count,:description,:create_date,:update_date, :policy_doc]
end

################################################################################
#
# This is the entrypoint. Custom sig engine will execute 'perform'
#
################################################################################
def perform(aws)
  finalized = false
  marker = nil

  # list_policies only return max 100 policies per API call.
  # scope set to 'Local' to list only the customer managed policies
  while finalized == false 
    if marker != nil
      resp = aws.iam.list_policies(scope: 'Local', marker: marker)
    else
      resp = aws.iam.list_policies(scope: 'Local')
    end

    #Setting the marker for the next call if the result is truncated
    if resp[:is_truncated]
      marker = resp[:marker]
    else
      finalized = true
    end

    resp[:policies].each do | policy |
      set_data(policy)
      policy_info = has_admin_access(aws,policy[:arn])
      set_data(admin_access: policy_info[:admin_access], policy_doc: policy_info[:policy_doc])

      if policy_info[:admin_access]
        if @options[:warn_if_not_attached] 
          if policy[:attachment_count]  < 1
            warn(message: "Managed policy [#{policy[:policy_name]}] has admin access. Alert set to warn because the policy has no attachment", resource_id: policy[:policy_name])
          else
            fail(message: "Managed policy [#{policy[:policy_name]}] has admin access and has attachment", resource_id: policy[:policy_name])
          end

        else
          fail(message: "Managed policy [#{policy[:policy_name]}] has admin access", resource_id: policy[:policy_name])
        end

      else
        pass(message: "Managed policy [#{policy[:policy_name]}] does not have full admin access ", resource_id: policy[:policy_name])
      end
    end
        


  end
end


################################################################################
#
# The policy checker
# For simplicity, admin policy statement looks like
# - Effect: Allow
# - Action: * or iam:*
# - Resource: *
#
################################################################################
def has_admin_access(aws,policy_arn)
  policy_detail = aws.iam.get_policy(policy_arn: policy_arn).policy

  policy_doc = aws.iam.get_policy_version({
    policy_arn: policy_arn,
    version_id: policy_detail[:default_version_id]
    }).policy_version.document

  # policy doc is URI encoded.
  policy_doc = JSON.parse(URI.decode(policy_doc)) if policy_doc.is_a? String
  output = { policy_doc: policy_doc, admin_access: false}

  # Policy doc with a single statement can also be written as 
  # Statement => {
  #          "Effect" : xxxxx,
  #          "Action" : xxxxx,
  #          "Resource": xxxxx,
  # }
  # instead of
  # Statement => [ {statement1}, {statement2}, etc]
  if policy_doc['Statement'].is_a? Hash
    output[:admin_access] = true if statement_has_admin?(policy_doc['Statement'])
  else
    # For policydoc with multiple statements
    # Statement => [ {statement1}, {statement2}, etc]
    policy_doc['Statement'].each do | statement |
      output[:admin_access] = true if statement_has_admin?(statement)
    end
  end

  return output

end

# Evaluate IAM policy statement
# Action and resource can be specified as a string for a single entry, or array
# Checking both for better check coverage
def statement_has_admin?(statement)
  # Evaluate Effect
  if statement['Effect'] != 'Allow'
    return false
  end

  # Evaluate Action
  has_blacklisted_action = false
  if statement['Action'].is_a? Array
    has_blacklisted_action = true if statement['Action'].include?("*")
  else
    has_blacklisted_action = true if statement['Action'] == "*"
  end

  return false if has_blacklisted_action == false

  # Now evaluate resource
  has_blacklisted_resource = false
  if statement['Resource'].is_a? Array
    has_blacklisted_resource = true if statement['Resource'].include?("*")
  else
    has_blacklisted_resource = true if statement['Resource'] == "*"
  end

  if has_blacklisted_resource
    return true
  else
    return false
  end

end