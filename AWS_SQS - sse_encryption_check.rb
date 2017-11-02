#
# Copyright (c) 2013, 2014, 2015, 2016, 2017. Evident.io (Evident). All Rights Reserved. 
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
# Check for SQS encryption setting (using KMS)
# 
# Default Conditions:
# - PASS: SQS has encryption enabled
# - FAIL: SQS does not have SQS encryption enabled
#
# Resolution/Remediation:
# - Open SQS console: https://console.aws.amazon.com/sqs
# - Select the queue
# - Select the [Queue Actions] dropdown menu.
# - Select [Configure Queue]
# - Check [Use SSE] and select the KMS key
# - [Save Changes]


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
  exclude_on_tag: [],

  # Case sensitivity when comparint the tag key & value
  case_insensitive: true,


}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:queue_arn, :queue_url, :created_time,  :last_modified, :kms_key_id]
end

def perform(aws)
  aws.sqs.list_queues[:queue_urls].each do | queue_url |
    queue_attributes = aws.sqs.get_queue_attributes(queue_url: queue_url, attribute_names: ["All"])[:attributes]
    queue_arn =  queue_attributes["QueueArn"]

    set_data({
      queue_arn: queue_attributes["QueueArn"],
      queue_url: queue_url,
      created_time: queue_attributes["CreatedTimestamp"],
      last_modified: queue_attributes["LastModifiedTimestamp"]
      })
    if queue_attributes.key?("KmsMasterKeyId")
      set_data(kms_key_id: queue_attributes["KmsMasterKeyId"])
      pass(message: "SQS queue #{queue_arn} has encryption enabled", resource_id: queue_arn)
    else
      if @options[:exclude_on_tag].count > 0

        begin
          tags = aws.sqs.list_queue_tags(queue_url: queue_url)[:tags]
          if get_tag_matches(@options[:exclude_on_tag], tags).count > 0
            pass(message: "SQS queue #{queue_arn} does not have encryption enabled. Alert set to pass due to the tags", resource_id: queue_arn, tags: tags, options: @options)
            next
          end          
        rescue StandardError => e
          if e.message.include?("undefined method") or e.message.include?("NoMethodError")
            # AWS ruby SDK v2 and v3 should have [list_queue_tags] method
            # Fall back to fail alert. AWS SDK 3.0.1 is missing [list_queue_tags] method.
          else
            error(message: "Encountered error when getting tag for #{queue_arn}.", error: e.message, resource_id: queue_arn)
            next
          end
        end
        
      end

      fail(message: "SQS queue #{queue_arn} does not have encryption enabled", resource_id: queue_arn)

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