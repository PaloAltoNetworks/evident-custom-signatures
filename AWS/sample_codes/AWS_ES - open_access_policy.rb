# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
# 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's
#   customers; and (b) any works created by Evident.io prior to its commencement of any
#   Services for Customer.
# 
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations
#   of the Customer as they relate to the Evident.io platform and products, and always
#   subject to Evident.io's underlying intellectual property rights.
# 
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF EVIDENT.IO HAS BEEN HAS BEEN
#   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#   THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#   EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
#   OR MODIFICATIONS.
#
# Description:
#
# Ensure ElasticSearch Domains do not have an Open Access Policy.
# 
# Default Conditions: 
#
# - FAIL: ElasticSearch domain has an open access policy
# - PASS: ElasticSearch domain does not have an open access policy
#
# Remediation:
#
# https://aws.amazon.com/blogs/security/how-to-control-access-to-your-amazon-elasticsearch-service-domain
#

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#

configure do |c|
  c.deep_inspection = [:domain_id, :arn, :endpoint, :access_policies, :region]
end

def perform(aws)

  domains = aws.elastic_search.list_domain_names[:domain_names]
  region  = aws.region
    
  domains.each do | domain |
    domain_name = domain[:domain_name]

    domain_status_list = aws.elastic_search.describe_elasticsearch_domains({ domain_names: [domain_name] })[:domain_status_list]
        
    domain_status_list.each do | status |
      domain_id  = status[:domain_id]
      endpoint   = status[:endpoint]
      policy_doc = status[:access_policies]
      arn        = status[:arn]

      access_policies = nil
      policy_fail     = 0
      condition_fail  = 0
            
      if policy_doc != ""
        access_policies = JSON.parse(URI.decode(policy_doc))
        policy          = access_policies.Statement
        
        policy.each do | statement |
          effect    = statement.Effect
          principal = statement.Principal.AWS
          action    = statement.Action
          condition = statement.Condition
          
          if condition != nil && condition.has_key?("IpAddress")
            ip_addresses = condition.IpAddress["aws:SourceIp"]
            ip_addresses.each do | ip |
              condition_fail += 1 if ip == "0.0.0.0/0" || ip == "::/0"
            end
          end
                
          if (effect == "Allow" && principal == "*" && action == "es:*" && condition == nil) ||
             (effect == "Allow" && principal == "*" && action == "es:*" && condition_fail > 0)
            policy_fail += 1
          end
        end
      end

      set_data(domain_id: domain_id, arn: arn, endpoint: endpoint, access_policies: access_policies, region: region)

      if policy_fail > 0
        fail(message: "ElasticSearch domain #{domain_name} has an open access policy.", resource_id: domain_name)
      elsif access_policies == nil
        pass(message: "ElasticSearch domain #{domain_name} has no access policy.", resource_id: domain_name)
      else
        pass(message: "ElasticSearch domain #{domain_name} has a restricted access policy.", resource_id: domain_name)
      end

    end
  end
end
