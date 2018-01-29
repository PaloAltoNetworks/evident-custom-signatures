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
# Check for S3 bucket policy 
# This signature checks S3 bucket policy against 'required_policies' and 'whitelisted_buckets'

# 
# Default Conditions:
# - PASS: The required policy is attached
# - FAIL: The required policy is not attached
#
# Resolution/Remediation:
# - Attach the required policy
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
  # If one or more of the required polices are not attached and the bucket is not in the 'white list',
  # a FAIL alert will be generated
  # 
  # Case sensitive
  
  required_policy: [
    "Gadourys S3 Bucket Policy"  
  ],
  
  # List of white listed bucket names
  # If one or more of the required polices are not attached and the bucket is not in the 'white list',
  # a FAIL alert will be generated
  # 
  # Case sensitive
  bucket_whitelist: [
    "evident-hermann"
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
    c.deep_inspection   = [:bucket_name, :creation_date, :policy_doc, :attached_policy, :required_policy]
    #c.valid_regions = [:us_east_1]
end


def perform(aws)

  if @options[:required_policy].count < 1
    error(message: "Required_Policies cannot be empty")
    return
  end

  required_policy = @options[:required_policy]

  set_data(required_policy: required_policy)
  
  begin
    aws.s3.list_buckets[:buckets].each do |resource|
        @options[:bucket_whitelist].each do | bucket_name |
            resource_name = resource[:name]
            
            if bucket_name == resource_name
                pass(message: "Bucket #{resource_name} is whitelisted", resource_id: resource_name)
                #return
            else
                check_resource(resource,aws)
            end
        end
    end
  rescue StandardError => e
    error(message: "Error in getting the bucket list", error: e.message)
    return  
  end
  
end


def check_resource(resource,aws)

  required_policy = @options[:required_policy][0]
  set_data(required_policy: required_policy)

  begin
    resource_name = resource[:name]

    bucket_location = aws.s3.get_bucket_location(bucket: resource_name)[:location_constraint]

    if bucket_location == ""
      return if aws.region != "us-east-1"
    elsif bucket_location != aws.region
      return
    end


    policy_doc = aws.s3.get_bucket_policy({bucket: resource_name})[:policy].read
    if policy_doc.is_a? String
      policy_doc = JSON.parse(policy_doc)
    end

    attached_policy = policy_doc["Id"]
    set_data(attached_policy: attached_policy)
    

    set_data(resource)
    set_data(policy_doc: policy_doc)

    if (required_policy != attached_policy) or (attached_policy.empty?)
      fail(message: "Bucket #{resource_name} one or more has offending policy statements", resource_id: resource_name)
    else
      pass(message: "Bucket #{resource_name} does not have offending policy statement nor exposed publicly", resource_id: resource_name)
    end

  rescue StandardError => e
    if e.message.include?("The bucket policy does not exist")
      fail(message: "Bucket #{resource_name} does not have any policy set", resource_id: resource_name)
    else
      error(message: "Error in processing bucket #{resource_name}. Error: #{e.message}", resource_id: resource_name)
    end

    return
  end
end

