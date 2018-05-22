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
# ALB security policy check
# 
# Default Conditions:
# - PASS: ALB listener does not use any blacklisted security policy
# - FAIL: ALB listener has one (or more) blacklisted protocols and/or ciphers.
#
# Resolution/Remediation:
# - Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.
# - On the navigation pane, under LOAD BALANCING, choose Load Balancers.
# - Select the load balancer.
# - On the Listeners tab, check the HTTPS listener, choose Action, then Edit.
# - Under [Select Security Policy], change to a different policy.
#
# Information about the policy can be found below
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # List of blacklisted Security Policy
  # Different from ELB, AWS does not allow the creation of custom security policy for ALB
  # Valid options as of Jan 2018:
  # - ELBSecurityPolicy-2016-08
  # - ELBSecurityPolicy-TLS-1-2-2017-01
  # - ELBSecurityPolicy-TLS-1-1-2017-01
  # - ELBSecurityPolicy-2015-05            <== same as ELBSecurityPolicy-2016-08
  # - ELBSecurityPolicy-TLS-1-0-2015-04
  blacklisted_policies: [
    "ELBSecurityPolicy-TLS-1-0-2015-04",
  ],

  # When a resource has one or more matching tags, the resource will be excluded from the checks
  # and a PASS alert is generated
  # Example:
  # exclude_on_tag: [
  #     {key: "environment", value: "demo"},
  #     {key: "environment", value: "dev*"}
  # ]
  # For wildcard, use *  . If set value: "*", it will match any value inside of the tag
  #
  # WARNING: For some AWS Services, pulling tags may require additional API call. 
  #          Therefore, tag information will be pulled
  #          if there is one or more tags specified in 'exclude_on_tag'
  exclude_on_tag: [],

  # Case sensitivity when comparing the tag key & value
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
    c.deep_inspection   = [:load_balancer_arn, :load_balancer_name, :offending_listeners, :listeners, :options]
end

def perform(aws)
  if @options[:exclude_on_tag].count > 0
    tag_list = get_resource_tags(aws, "elasticloadbalancing:loadbalancer")
    puts JSON.dump(tag_list)
  end


  aws.elbv2.describe_load_balancers[:load_balancers].each do | alb |
    # Only check ALB
    next if alb[:type] != "application"

    load_balancer_arn = alb[:load_balancer_arn]
    load_balancer_name = alb[:load_balancer_name]

    # we need a separate call to get ALB tags.
    # So, tag is grabbed only if necessary
    if @options[:exclude_on_tag].count > 0
      tags = tag_list[load_balancer_arn]
      if get_tag_matches(@options[:exclude_on_tag], tags).count > 0
        pass(message: "ALB #{load_balancer_name} is skipped due to the tags", options: @options)
        next
      end
    end

    offending_listeners = []
    listeners = aws.elbv2.describe_listeners(load_balancer_arn: load_balancer_arn)[:listeners]
    listeners.each do | listener |
      next if listener[:protocol] != "HTTPS"
      offending_listeners.push(listener) if @options[:blacklisted_policies].include?(listener[:ssl_policy])
    end

    set_data(
      load_balancer_arn: load_balancer_arn,
      load_balancer_name: load_balancer_name,
      offending_listeners: offending_listeners,
      listeners: listeners,
      options: @options
      )

    if offending_listeners.count > 0
      fail(message: "ALB #{load_balancer_name} has one or more offending listeners", resource_id: load_balancer_name)
    else
      pass(message: "ALB #{load_balancer_name} does not have any offending listeners", resource_id: load_balancer_name)
    end
  end
end


#############################################################################
# Return the matching tags if one of the tag key-value pair matches
# or empty array if there is no matching tags
##############################################################################
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

##########################################################################################################
# Return tags for a speficic namespace
# See this page for the list of namespaces
# http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces
##########################################################################################################
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
        resource_arn = tag_mapping[:resource_arn]
        output[resource_arn] = tag_mapping[:tags]
      end

      if resp[:pagination_token].empty? or resp[:pagination_token].nil?
        pagination_token = "end"
      else
        pagination_token = resp[:pagination_token]
      end
    end

  rescue StandardError => e
    return output
  end

  return output
end