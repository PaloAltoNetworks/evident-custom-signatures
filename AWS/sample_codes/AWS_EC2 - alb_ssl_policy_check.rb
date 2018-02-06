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
# Check SSL ciphers on ALB listeners  
# 
# Default Conditions:
# - PASS: ALB listener does not use any blacklisted protocols or ciphers.
# - FAIL: ALB listener has one (or more) blacklisted protocols and/or ciphers.
# - WARN: ALB listener has one (or more) blacklisted protocols and/or ciphers, but the resource tag matches 'warn_only_on_tag'
#
# Resolution/Remediation:
# - Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
# - On the navigation pane, under LOAD BALANCING, choose Load Balancers.
# - Select the load balancer.
# - On the Listeners tab, check the HTTPS listener, choose Action, then Edit.
# - Under [Select Security Policy], change to a different policy.
#
# Information about the policy can be found below
# http://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
# BLACKLIST
  # ALB protocols support TLSv1 or above.
  # As of 5/10/2017, available options are:
  # TLSv1, TLSv1.1 , TLSv1.2
  protocol_blacklist: ['TLSv1'],

  # ALB cipher blacklist.
  # Refer to the link in the header section for a valid list of ciphers
  cipher_blacklist: [],


# EXCLUSION
  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and a PASS alert is generated
  # Example:
  # exclude_on_tag: [
  #     {key: "skipped", value: "yeah"},
  #     {key: "skipped", value: "ye*"}
  # ]
  # For wildcard, use *  . If you set value: "*", it will match everything inside of 'value'.
  # You can use it if you want to ensure that the tag exists (regardless what the value is)
  #
  # WARNING: Pulling tags requires an additional API call. Therefore, tag information will be pulled only
  #          if you have one or more tags specified in 'exclude_on_tag'
  exclude_on_tag: [],

# CONDITIONAL
  # Case sensitivity when comparint the tag key & value
  case_insensitive: true,

  # When a resource fails the check, resources with matching tags will
  # generate WARN alert instead of FAIL
  # Example:
  # warn_only_on_tag: [
  #         {key: "environment", value: "stage"},
  #         {key: "environment", value: "dev"}
  #]
  # For wildcard, use *  . If set value: "*", it will match everything inside of 'value'.
  # You can use it if you want to ensure that the tag exists (regardless what the value is)
  #
  # WARNING: Pulling tags requires an additional API call. Therefore, tag information will be pulled only
  #          if you have one or more tags specified in 'warn_only_on_tag'
  warn_only_on_tag: [],
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:load_balancer_arn, :load_balancer_name, :listeners ]
end

def perform(aws)
  ssl_policies = process_ssl_policies(aws.elbv2.describe_ssl_policies[:ssl_policies])

  alb_details = {}
  alb_arns = []
  aws.elbv2.describe_load_balancers[:load_balancers].each do | alb |
    alb_arns.push(alb[:load_balancer_arn])
    alb_details[alb[:load_balancer_arn]] = {
      load_balancer_arn: alb[:load_balancer_arn],
      load_balancer_name: alb[:load_balancer_name]
    }
  end

  # we need a separate call to get ALB tags.
  # So, tag is grabbed only if necessary
  if @options[:exclude_on_tag].count > 0 || @options[:warn_only_on_tag].count > 0
    tags = aws.elbv2.describe_tags(resource_arns: alb_arns)[:tag_descriptions]
    tags.each do | tag |
      alb_details[tag[:resource_arn]][:tags] = tag[:tags]
    end
  end

  # Check each ALB, check each listener in the ALB
  alb_details.keys.each do | alb_arn |
    alb_name = alb_details[alb_arn][:load_balancer_name]

    # Skipping ALB checks if the ALB has tags specified in 'exclude_on_tags'.
    if @options[:exclude_on_tag].count > 0 && get_tag_matches(@options[:exclude_on_tag], alb_details[alb_arn][:tags]).count > 0
      pass(message: "ALB skipped due to exclude_on_tag", resource_id: alb_name, exclude_on_tag: @options[:exclude_on_tag])
      next
    end

    offending_listeners = []
    listeners = aws.elbv2.describe_listeners(load_balancer_arn: alb_arn)[:listeners]



    listeners.each do | listener |
      next if listener[:protocol] == "HTTP"

      #if the listener has offending ssl protocol or ciphers, add the listener to the offending_listeners
      ssl_protocols = ssl_policies[listener[:ssl_policy]][:ssl_protocols]
      ssl_ciphers = ssl_policies[listener[:ssl_policy]][:ciphers]
      if (ssl_protocols & @options[:protocol_blacklist]).count > 0  || (ssl_ciphers & @options[:cipher_blacklist]).count > 0
        listener_info = {
          listener_arn: listener[:listener_arn],
          port: listener[:port],
          protocol: listener[:protocol],
          protocol_blacklist: @options[:protocol_blacklist],
          cipher_blacklist: @options[:cipher_blacklist],
          ssl_policy_details: ssl_policies[listener[:ssl_policy]],
        }
        offending_listeners.push(listener_info)
        next
      end
    end

    set_data(alb_details[alb_arn])
    set_data(listeners: listeners)


    if offending_listeners.count == 0
      pass(message: "ALB #{alb_name} does not have any offending SSL protocol or cipher", resource_id: alb_name)
    else
      set_data(offending_listeners: offending_listeners)
      if @options[:warn_only_on_tag].count > 0 && alb_details[alb_arn][:tags].count > 0 && get_tag_matches(@options[:warn_only_on_tag], alb_details[alb_arn][:tags]).count > 0
        warn(message: "ALB #{alb_name} has offending SSL protocol and/or cipher. Alert set to warn due to warn_only_on_tag", resource_id: alb_name, warn_only_on_tag: @options[:warn_only_on_tag], offending_listeners: offending_listeners)
      else
        fail(message: "ALB #{alb_name} has offending SSL protocol and/or cipher.", resource_id: alb_name, offending_listeners: offending_listeners)
      end
    end
  end

end


# Unpack SSL policies
# output: {
#   "policy_name" => {
#       ssl_protocols: [],
#       ciphers: []
#   }
# }
# 
def process_ssl_policies(raw_policies)
  policies = {}

  raw_policies.each do | raw_policy|
    policies[raw_policy[:name]] = {
      ssl_protocols: raw_policy[:ssl_protocols],
      ciphers: []
    }

    raw_policy[:ciphers].each do | cipher |
      policies[raw_policy[:name]][:ciphers].push(cipher[:name])
    end
  end

  return policies
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