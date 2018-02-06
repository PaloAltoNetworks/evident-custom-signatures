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
# Check for S3 bucket lifecycle configuration
# 
# Default Conditions:
# - PASS: S3 bucket has bucket lifecycle configuration
# - FAIL: S3 bucket does not have bucket lifecycle configuration
#
# Resolution/Remediation:
# - Open the Amazon S3 console at https://console.aws.amazon.com/s3/
# - Select the target bucket
# - Click on [Management] tab
# - Click on [+ Add Lifecycle rule]
# - Follow the guide to create a lifecycle rule
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
  #     {key: "skipped", value: "demo"},
  #     {key: "skipped", value: "dev*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  # WARNING: Pulling tags requires additional API call. Therefore, tag information will be pulled
  #          if there is one or more tags specified in 'exclude_on_tag'
  exclude_on_tag: [
    {key: "environment", value: "demo*"}
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

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:bucket_name, :bucket_location, :lifecycle_rules, :tags, :options]
end


def perform(aws)
  aws.s3.list_buckets[:buckets].each do |bucket|
    begin
      bucket_name = bucket[:name]

      # The signature runtime is tied to a region.
      # To avoid the redirection error for dns named bucket,
      # Buckets are evaluated per region. Bucket on another region will be skipped
      bucket_location = aws.s3.get_bucket_location(bucket: bucket_name).location_constraint
      if bucket_location == ""
        next if aws.region != "us-east-1"
      elsif bucket_location != aws.region
        next
      end

      bucket_exclusion_cause = get_bucket_exclusion_cause(aws,bucket_name)
      if bucket_exclusion_cause != ""
        set_data(bucket_name: bucket_name, bucket_location: bucket_location, options: @options)
        pass(message: "Bucket #{bucket_name} is skipped from the check due to the #{bucket_exclusion_cause}", resource_id: bucket_name)
        next
      end

      begin
        lifecycle_rules = aws.s3.get_bucket_lifecycle_configuration(bucket: bucket_name)[:rules]
        set_data(lifecycle_rules: lifecycle_rules)
        pass(message: "S3 bucket #{bucket_name} has lifecycle rule(s) set", resource_id: bucket_name)
      rescue StandardError => e
        set_data(lifecycle_rules: nil)
        if e.message.include?("The lifecycle configuration does not exist")
          fail(message: "S3 bucket #{bucket_name} does not have lifecycle rule set", resource_id: bucket_name, error: e.message)
        else
          error(message: "Failed to get S3 bucket #{bucket_name} lifecycle rule", resource_id: bucket_name, error: e.message)
        end
        
      end
  

    rescue StandardError => e
      error(message: "Error in processing bucket #{bucket_name}", error: e.message, resource_id: bucket_name)
      next
    end
  end
end



def get_bucket_exclusion_cause(aws, bucket_name)
  # Check to see if the bucket should be included base on its tags
  if @options[:exclude_on_tag].count > 0
    begin
      tags = aws.s3.get_bucket_tagging({bucket: bucket_name})[:tag_set]
      set_data(tags: tags) 
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