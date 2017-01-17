##
## elastic_search_open_access_policy.rb - John Martinez (john@evident.io)
##
## Name: Elasticsearch Domain with Open Access Policy
##
## Severity Level: High
##
## Description
## Elasticsearch domains control access via an access policy. This signature checks for
## an access policy with open access.
## 
## Resolution
## Go to the Elasticsearch service in the AWS Console and modify the access policy to
## a specific permission other than a global permission.
## 
configure do |c|
    c.deep_inspection = [:domain_id, :arn, :endpoint, :access_policies]
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
            
            domain_id  = domain_status[:domain_id]
            arn = domain_status[:arn]
            endpoint = domain_status[:endpoint]
            policy_doc = domain_status[:access_policies]
            access_policies = JSON.parse(URI.decode(policy_doc))
            
            fail_count = 0
            
            policy = access_policies.Statement
            
            effect = nil
            principal = nil
            action = nil
            
            policy.each do |policy_statement|
                
                effect = policy_statement["Effect"]
                principal = policy_statement["Principal"]["AWS"]
                action = policy_statement["Action"]
                
                if effect == "Allow" && principal == "*" && action == "es:*"
                    fail_count += 1
                end
                
            end

            set_data(domain_id: domain_id, arn: arn, endpoint: endpoint, access_policies: access_policies)

            if fail_count > 0
                fail(message: "Elasticsearch domain #{domain_name} has an open access policy", resource_id: domain_name)
            else
                pass(message: "Elasticsearch domain #{domain_name} has a restricted access policy", resource_id: domain_name)
            end
            
        end
        
    end

end
