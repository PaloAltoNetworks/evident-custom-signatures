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
# Alert trigger based on S3 Bucket tags.
# 
# Default Conditions:
#
# - FAIL: S3 bucket has no tags, or does not match all specified tags in the trigger
# - PASS: S3 bucket matches all tags specified in the trigger
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
#

@options = {  
  # You can specify multiple tags for the trigger. 
  # If all tags are found, a PASS alert is generated
  # Example:
  # tag_trigger: [
  #     {key: "environment", value: "dev*"},
  #     {key: "required_tag_x", value: "*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  tag_trigger: [
    { key: "Application_ID", value: "*" },
    { key: "Environment", value: "*" },
    { key: "Data_Class", value: "*" },
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
  exclude_bucket_on_regex: nil,

  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and a PASS alert is generated
  # Example:
  # exclude_on_tag: [
  #     {key: "skipped", value: "yeah"},
  #     {key: "skipped", value: "ye*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  exclude_on_tag: [
  ],
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
#
                                                                      
configure do |c|
  c.deep_inspection   = [:bucket_name, :bucket_location, :tags, :options]
end

def perform(aws)

  tag_list = get_resource_tags(aws,"s3")

  aws.s3.list_buckets[:buckets].each do |bucket|
    begin
      bucket_name = bucket[:name]

      # The signature runtime is tied to a region.
      # To avoid the redirection error for dns named bucket,
      # Buckets are evaluated per region. Bucket on another region will be skipped
      begin
        bucket_location = aws.s3.get_bucket_location(bucket: bucket_name).location_constraint
      rescue StandardError => e
        warn(message: "#{e} S3 bucket: #{bucket_name}", resource_id: bucket_name)
        next
      end
      
      if bucket_location == ""
        next if aws.region != "us-east-1"
      elsif bucket_location != aws.region
        next
      end

      if tag_list.key?(bucket_name)
        tags = tag_list[bucket_name]
      else
        tags = []
      end

      set_data(bucket_name: bucket_name, bucket_location: bucket_location, tags: tags, options: @options)
      bucket_exclusion_cause = get_bucket_exclusion_cause(aws,bucket_name, tags)
      
      if bucket_exclusion_cause != ""
        pass(message: "Bucket #{bucket_name} is skipped from the check due to the #{bucket_exclusion_cause}", resource_id: bucket_name)
      else
        if get_tag_matches(@options[:tag_trigger], tags).count == @options[:tag_trigger].count
          pass(message: "All matching bucket tags were found.", resource_id: bucket_name)
        else
          fail(message: "Matching bucket tags were not found.", resource_id: bucket_name)
        end
      end
    end
  end
end


def get_bucket_exclusion_cause(aws, bucket_name, tags = [])
  # Check to see if the bucket should be excluded base on its tags
  return "tags" if get_tag_matches(@options[:exclude_on_tag], tags).count > 0

  # Check to see if bucket is listed in bucket_whitelist
  return "bucket_whitelist" if @options[:bucket_whitelist].include?(bucket_name)

  # Check to see if bucket should be excluded based on regex
  if @options[:exclude_bucket_on_regex].nil? == false
    return "regex" if bucket_name.match(@options[:exclude_bucket_on_regex])
  end

  return "" 
end


# Return tags for a speficic namespace
# See this page for the list of namespaces
# http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces
def get_resource_tags(aws, resource_namespace)
  output = {}

  begin
    pagination_token = nil

    while pagination_token != "end"
      resp = aws.resource_groups_tagging.get_resources({
        resources_per_page: 50,
        resource_type_filters: [resource_namespace],
        pagination_token: pagination_token
        })

      resp[:resource_tag_mapping_list].each do | tag_mapping |
        resource_name = tag_mapping[:resource_arn].split(':').last
        output[resource_name] = tag_mapping[:tags]
      end

      if resp[:pagination_token].empty? or resp[:pagination_token].nil?
        pagination_token = "end"
      else
        pagination_token = resp[:pagination_token]
      end
    end

  rescue StandardError => e
    # do nothing
  end

  return output
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
