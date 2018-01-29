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
# Check S3 bucket policy for Server Side Encryption setting
# http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html
#
# For simplicity, per AWS documentation above, SSE is considered as enabled the bucket has one of the following
# conditions in the statement
# Option 1: 
# {
#   "Sid": "DenyIncorrectEncryptionHeader",
#   "Effect": "Deny",
#   "Principal": "*",
#   "Action": "s3:PutObject",
#   "Resource": "arn:aws:s3:::YourBucket/*",
#   "Condition": {
#     "StringNotEquals": {
#       "s3:x-amz-server-side-encryption": "AES256"
#     }
#   }
# }
#
# Option 2:
# {
#   "Sid": "DenyUnEncryptedObjectUploads",
#   "Effect": "Deny",
#   "Principal": "*",
#   "Action": "s3:PutObject",
#   "Resource": "arn:aws:s3:::YourBucket/*",
#   "Condition": {
#     "Null": {
#      "s3:x-amz-server-side-encryption": "true"
#    }
#   }
# }
#
# 
# Default Conditions:
# - PASS: S3 bucket has SSE enabled
# - FAIL: S3 bucket does not have SSE enabled, or does not have S3 bucket policy set
#
# Resolution/Remediation:
# - Adjust the S3 bucket policy to enable SSE
#


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options    
@options = {
  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and a PASS alert is generated
  # Example:
  # exclude_on_tag: [
  #     {key: "environment", value: "demo"},
  #     {key: "environment", value: "dev*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  # WARNING: Pulling tags requires additional API call. Therefore, tag information will be pulled
  #          if there is one or more tags specified in 'exclude_on_tag'
  exclude_on_tag: [
  ],


  # Case sensitivity when comparint the tag key & value
  case_insensitive: true,


  # List the buckets that you want to be excluded from the checks.
  # Case Sensitive
  # Example:
  #  bucket_whitelist: ['www.mywebsite.com', 'www.yourwebsite.com'],
  bucket_whitelist: [],


  # If you specify a regex, bucket that match the regex will be excluded from the check
  # Example:
  # to exclude wwww.something.com (i at the end for case insensitive)
  #       exclude_bucket_on_regex: /^www\..*$/i ,
  # to exclude demo-bucket-<something>
  #       exclude_bucket_on_regex: /demo-bucket-.*/,
  exclude_bucket_on_regex: nil ,
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:bucket_name, :creation_date, :offending_statements, :policy_doc, :options, :encryption_config]
end


def perform(aws)
  begin
    aws.s3.list_buckets[:buckets].each do |resource|
      check_resource(resource,aws)
    end
  rescue StandardError => e
    warn(message: "Error in getting the bucket list", error: e.message)
    return  
  end
  
end



def check_resource(resource,aws)
  begin
    resource_name = resource[:name]

    bucket_location = aws.s3.get_bucket_location(bucket: resource_name)[:location_constraint]

    if bucket_location == ""
      return if aws.region != "us-east-1"
    elsif bucket_location != aws.region
      return
    end

    bucket_exclusion_cause = get_bucket_exclusion_cause(aws,resource_name)
    if bucket_exclusion_cause != ""
      set_data(resource)
      set_data(options: @options)
      pass(message: "Bucket #{resource_name} is skipped from the check due to the #{bucket_exclusion_cause}", resource_id: resource_name)
      return
    end

    # Bucket is not excluded from the check.

    # Check to see if SSE is enabled through bucket settings (new S3 feature)
    begin
      encryption_config = aws.s3.get_bucket_encryption(bucket: resource_name)[:server_side_encryption_configuration][:rules]
      set_data(encryption_config: encryption_config)
      pass(message: "Bucket #{resource_name} has SSE enabled through bucket config", resource_id: resource_name)
      return
    rescue StandardError => e
      if e.message.include?("server side encryption configuration was not found") == false
        warn(message: "Encountered error when getting the bucket encryption", error: e.message, resource_id: resource_name)
        return
      end
    end

    # Grabbing the policy doc...
    policy_doc = aws.s3.get_bucket_policy({bucket: resource_name})[:policy].read
    if policy_doc.is_a? String
      policy_doc = JSON.parse(policy_doc)
    end
    
    sse_enforced = check_sse_enforcement(policy_doc)

    set_data(resource)
    set_data(policy_doc: policy_doc, options: @options)

    if sse_enforced
      pass(message: "Bucket #{resource_name} has SSE enforced", resource_id: resource_name)
    else
      fail(message: "Bucket #{resource_name} does not have SSE enforced", resource_id: resource_name)
    end

  rescue StandardError => e
    if e.message.include?("The bucket policy does not exist")
      fail(message: "Bucket #{resource_name} does not have any policy set", resource_id: resource_name)
    else
      warn(message: "Error in processing bucket #{resource_name}. Error: #{e.message}", resource_id: resource_name)
    end

    return
  end
end



def get_bucket_exclusion_cause(aws, bucket_name)
  # Check to see if the bucket should be included base on its tags
  if @options[:exclude_on_tag].count > 0
    begin
      tags = aws.s3.get_bucket_tagging({bucket: bucket_name})[:tag_set]  
      return "tags" if get_tag_matches(@options[:exclude_on_tag], tags).count > 0
    rescue StandardError => e
      if e.message.include?("The TagSet does not exist")
      # do nothing
      end
    end
  end

  # Check to see if bucket is listed in bucket_whitelist
  return "bucket_whitelist" if @options[:bucket_whitelist].include?(bucket_name)

  # Check to see if bucket should be excluded based on regex
  if @options[:exclude_bucket_on_regex].nil? == false
    return "regex" if bucket_name.match(@options[:exclude_bucket_on_regex])
  end

  return "" 
end


# Return true if S3 bucket has SSE enforcement
# it will return false if all S3 policy statement has been evaluated 
# and no SSE enforcement is found
def check_sse_enforcement(policy_doc)
  if policy_doc['Statement'].is_a? Hash 
    return true if statement_has_sse?(policy_doc['Statement'])

  else
    policy_doc['Statement'].each do | statement |
        return true if statement_has_sse?(statement)
    end

  end

  return false
end


#####################################################################################
#
# For simplicity, we assume that user will follow one of the documented way of
# enabling SSE, listed in this doc: 
# http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html
#
# Option 1: 
# {
#   "Sid": "DenyIncorrectEncryptionHeader",
#   "Effect": "Deny",
#   "Principal": "*",
#   "Action": "s3:PutObject",
#   "Resource": "arn:aws:s3:::YourBucket/*",
#   "Condition": {
#     "StringNotEquals": {
#       "s3:x-amz-server-side-encryption": "AES256"
#     }
#   }
# }
#
# Option 2:
# {
#   "Sid": "DenyUnEncryptedObjectUploads",
#   "Effect": "Deny",
#   "Principal": "*",
#   "Action": "s3:PutObject",
#   "Resource": "arn:aws:s3:::YourBucket/*",
#   "Condition": {
#     "Null": {
#      "s3:x-amz-server-side-encryption": "true"
#    }
#   }
# }
def statement_has_sse?(statement)
  return false if statement["Effect"] == "Allow"

  if statement["Action"].is_a? Array
    return false if ( statement["Action"] & ["s3:PutObject","s3:*","*"]).count < 1
  else
    return false if (["s3:PutObject","s3:*","*"].include?(statement["Action"]) == false)
  end

  # Check the principal. Require principal to be * or AWS:*
  if statement["Principal"].is_a? Hash
    return false if statement["Principal"]["AWS"] != "*"
  else
    return false if statement["Principal"] != "*"
  end      

  # Check condition
  if statement.key?("Condition")
    # OPtion 1
    if statement["Condition"].key?("StringNotEquals") and statement["Condition"]["StringNotEquals"].key?("s3:x-amz-server-side-encryption")
      sse = statement["Condition"]["StringNotEquals"]["s3:x-amz-server-side-encryption"].downcase
      return true if ["aes256","aws:kms"].include?(sse)
    end

    # Option 2
    if statement["Condition"].key?("Null") and statement["Condition"]["Null"].key?("s3:x-amz-server-side-encryption") and
      statement["Condition"]["Null"]["s3:x-amz-server-side-encryption"] == "true"
    then
      return true
    end
  end


  return false
end



# Return the number of matching tags if one of the tag key-value pair matches
def get_tag_matches(option_tags, aws_tags)
  matches = []

  option_tags.each do | option_tag |
    # If tag value is a string, do string comparison (with wildcard support)
    if option_tag[:value].is_a? String
      option_value = option_tag[:value].sub('*','.*')

      aws_tags.each do | aws_tag | 
        if @options[:case_insensitive]
          value_pattern = /^#{option_value}$/i
          matches.push(aws_tag) if option_tag[:key].downcase == aws_tag[:key].downcase and aws_tag[:value].match(value_pattern)
        else
          value_pattern = /^#{option_value}$/
          matches.push(aws_tag) if option_tag[:key] == aws_tag[:key] and aws_tag[:value].match(value_pattern)
        end          
      end

    # if tag value is an array, check if value is in the array
    else
      if @options[:case_insensitive]
        option_values = option_tag[:value].map(&:downcase)
      else
        option_values = option_tag[:value]
      end

      aws_tags.each do | aws_tag |
        if @options[:case_insensitive]
          matches.push(aws_tag) if (option_tag[:key].downcase == aws_tag[:key].downcase && (option_values.include?(aws_tag[:value].downcase)))
        else
          matches.push(aws_tag) if (option_tag[:key] == aws_tag[:key] && (option_values.include?(aws_tag[:value])))
        end
      end
    end
  end

  return matches
end
