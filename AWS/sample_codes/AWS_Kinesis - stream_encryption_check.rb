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
# Check Kinesis stream settings for encryption
# This custom signature requires additional permission:
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "kinesisInspect",
#       "Effect": "Allow",
#       "Action": [
#         "kinesis:ListStreams",
#         "kinesis:ListTagsForStream",
#         "kinesis:DescribeStream"
#       ],
#       "Resource": [
#         "*"
#       ]
#     }
#   ]
# }
# 
# Default Conditions:
# - PASS: Kinesis stream is encrypted
# - FAIL: Kinesis stream is not encrypted
#
# Resolution/Remediation:
# - Open Kinesis console: https://console.aws.amazon.com/kinesis
# - Click on the name of the stream you want to change
# - Under "Server-side encryption", select "Edit" button
# - Choose "Enabled" radio button
# - Choose KMS key
# - Hit "Save"


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
# EXCLUSION
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
  exclude_on_tag: [],

  # Case sensitivity when comparint the tag key & value
  case_insensitive: true,

  # Maximum number of list to be checked
  stream_limit: 100

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:stream_name, :stream_arn, :stream_status, :retention_period_hours, :encryption_type, :key_id, :tags]
end

def perform(aws)
  begin
    stream_names = aws.ks.list_streams(limit: @options[:stream_limit])[:stream_names]
  rescue StandardError => e
    error(message: "Unable to get the list of Kinesis streams. Please ensure that ESP has the proper access", error: e.message)
    return
  end

  stream_names.each do | stream_name |
    stream_info = aws.ks.describe_stream(stream_name: stream_name)[:stream_description]
    set_data(stream_info)

    if stream_info[:encryption_type] == "KMS"
      pass(message: "Kinesis stream #{stream_name} has encryption enabled", resource_id: stream_name)
    else
      if @options[:exclude_on_tag].count > 0
        tags = aws.ks.list_tags_for_stream(stream_name: stream_name)[:tags]
        set_data(tags: tags)
        if get_tag_matches(@options[:exclude_on_tag], tags).count > 0
          pass(message: "Kinesis stream #{stream_name} does not have encryption enabled. Alert set to pass due to the tags", resource_id: stream_name, options: @options)
          next
        end

      else
        fail(message: "Kinesis stream #{stream_name} does not have encryption enabled", resource_id: stream_name)
      end
    end

  end


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