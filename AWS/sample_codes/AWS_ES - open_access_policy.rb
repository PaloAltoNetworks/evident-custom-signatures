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
# Check fo Elasticsearch Domain with Open Access Policy
# 
# Elasticsearch domains control access via an access policy. This signature checks for
# an access policy with open access.
#
# John Martinez (john@evident.io)
# 
# Resolution
# Go to the Elasticsearch service in the AWS Console and modify the access policy to
# a specific permission other than a global permission.
# 
configure do |c|
    c.deep_inspection = [:domain_id, :arn, :endpoint, :access_policies]
    c.valid_regions = [:us_east_1, :us_east_2, :us_west_1, :us_west_2, :ap_south_1, :ap_northeast_2,
                        :ap_southeast_1, :ap_southeast_2, :ap_northeast_1, :eu_central_1, 
                        :eu_west_1, :sa_east_1]
    c.unique_identifier  = [:domain_name]
end

def perform(aws)
    domain_names = aws.elastic_search.list_domain_names.domain_names
    
    domain_names.each do |domain_name|
        
        domain_name = domain_name[:domain_name]

        domain_status_list = aws.elastic_search.describe_elasticsearch_domains({
            domain_names: [ domain_name ],
        }).domain_status_list
        
        domain_status_list.each do |domain_status|
            
            policy_doc = nil
            access_policies = nil
            
            domain_id  = domain_status[:domain_id]
            arn = domain_status[:arn]
            endpoint = domain_status[:endpoint]
            policy_doc = domain_status[:access_policies]
            
            fail_count = 0
            
            if policy_doc != ""
                
                access_policies = JSON.parse(URI.decode(policy_doc))
                policy = access_policies.Statement
            
                effect = nil
                principal = nil
                action = nil
                condition = nil
                source_ip = nil

                policy.each do |policy_statement|
                
                    effect = policy_statement["Effect"]
                    principal = policy_statement["Principal"]["AWS"]
                    action = policy_statement["Action"]
                    condition = policy_statement["Condition"]
                
                    if condition != nil && condition.has_key?("IpAddress")
                        source_ip = policy_statement["Condition"]["IpAddress"]["aws:SourceIp"]
                    else
                        source_ip = "N/A"
                    end
                
                    if effect == "Allow" && principal == "*" && action == "es:*" && (source_ip == nil || source_ip == "0.0.0.0/0")
                        fail_count += 1
                    end
                
                end
            
            end

            set_data(domain_id: domain_id, arn: arn, endpoint: endpoint, access_policies: access_policies)

            if fail_count > 0
                fail(message: "Elasticsearch domain #{domain_name} has an open access policy", resource_id: domain_name)
            else
                if access_policies == nil
                    pass(message: "Elasticsearch domain #{domain_name} has no access policies", resource_id: domain_name)
                else
                    pass(message: "Elasticsearch domain #{domain_name} has a restricted access policy", resource_id: domain_name)
                end
            end
            
        end
        
    end

end
