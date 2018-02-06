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


# Description:
# Get all Inspector findings and report them as FAIL alerts
# 
# Resolution:
# Read the finding description and recommendation to resolve.
#
# NOTES:
# In order for this custom signature to execute, you must attach a policy that permits
# Inspector List* and Describe* API calls, to the IAM Role for Evident.io. Not doing so
# will result in methods not being available due to the 'inspector' client being missing
# in the inherited AWS class.
#
# The "AmazonInspectorReadOnlyAccess" AWS-managed policy provides sufficient privelege
# for this custom signature to execute. arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess
#

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

