## 
## inspector_describe_findings.rb: Get all Inspector findings and report them as FAIL alerts
##
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2016 Evident.io, Inc., All Rights Reserved
##
## Description:
## List all Inspector findings in a region and generate finding details.
## 
## Resolution:
## Read the finding description and recommendation to resolve.
##
## NOTES:
## In order for this custom signature to execute, you must attach a policy that permits
## Inspector List* and Describe* API calls, to the IAM Role for Evident.io. Not doing so
## will result in methods not being available due to the 'inspector' client being missing
## in the inherited AWS class.
##
## The "AmazonInspectorReadOnlyAccess" AWS-managed policy provides sufficient privelege
## for this custom signature to execute. arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess
##

# Required configure loop. Place desired attributes in `c.deep_inspection`
configure do |c|
    c.deep_inspection = [:instance_id, :instance_tags, :arn, :id, :title, :description, :recommendation, :severity, :indicator_of_compromise, :created_at, :updated_at, :attributes]
    c.unique_identifier  = [:resource_id]
end

# Required perform method
def perform(aws)

    finding_arns = aws.inspector.list_findings.finding_arns
    
    finding_arns.each do |finding_arn|
        arn = finding_arn
        findings = aws.inspector.describe_findings({ finding_arns: [arn] }).findings

        findings.each do |finding|
            asset_attributes = finding.asset_attributes
            instance_id = asset_attributes.agent_id
            split_arn = arn.split(/\//)
            unique_key = split_arn[7]
            instance_tags = nil
            if instance_id == nil
                resource_id = "NOINSTANCE:#{unique_key}"
            else
                instance_tags = aws.ec2.describe_tags({
                    filters: [
                        {
                            name: "resource-id", 
                            values: [
                                instance_id, 
                            ], 
                        }, 
                    ], 
                }).tags

                resource_id = "#{instance_id}:#{unique_key}"
            end
            set_data(finding, instance_id: instance_id, instance_tags: instance_tags)
            fail(resource_id: resource_id)
        end
    end
    
end

