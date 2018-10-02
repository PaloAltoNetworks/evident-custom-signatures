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
# Check for API gateway's authorization (public invoke) 
#
# This custom signature requires additional permission:
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "apiGatewayInspect",
#       "Effect": "Allow",
#       "Action": [
#         "apigateway:GET"
#       ],
#       "Resource": [
#         "*"
#       ]
#     }
#   ]
# }
# 
# Default Conditions:
# - PASS: All methods have authorization set.
# - PASS: REST API has no stage(s) 
# - FAIL: One or more method has authorization set to None.

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # By default, all stages are evaluated.
  # List the stages that you want to exclude. Case sensitive
  # Example: excluded_stages: ['test', 'dev']
  excluded_stages: ['test']

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:open_methods, :api_methods, :rest_api_details, :stage_details]
end

def perform(aws)
  # Get available APIs
  rest_apis = aws.api_gateway.get_rest_apis[:items]

  rest_apis.each do | rest_api |
    api_id = rest_api[:id]
    api_name = rest_api[:name]

    # Each API can have multiple deployment to stages.
    stages = aws.api_gateway.get_stages(rest_api_id: api_id)[:item ]
    if stages.count < 1
      set_data(rest_api_details: rest_api)
      pass(message: "REST API #{api_name} does not have a stage", resource_id: (api_name + ':-'))
      next
    end

    stages.each do | stage |
      stage_name = stage[:stage_name]

      if @options[:excluded_stages].include?(stage_name)
        set_data(rest_api_details: rest_api, stage_details: stage)
        pass(message: "REST API #{api_name} is excluded from the scan", resource_id: "#{api_name}:#{stage_name}")
        next
      end

      # Get the deployment details
      #
      # embed: ["apisummary"] is so that we get the actual value of the method settings. Otherwise, we get null
      # Ruby SDK only support "apisummary" as of Aug 2017. This may change in the future
      deployment_details = aws.api_gateway.get_deployment(
          rest_api_id: api_id,
          deployment_id: stage[:deployment_id],
          embed: ["apisummary"]
        )

      api_methods = []
      open_methods = []

      deployment_details[:api_summary].each do | api_summary |
        # 
        path = api_summary[0]
        method_details = api_summary[1]

        method_details.each do | method_name, method_config |
          tmp = {
            path: path,
            method: method_name,
            authorization_type: method_config[:authorization_type]
          }

          api_methods.push(tmp)
          open_methods.push(tmp) if method_config[:authorization_type].downcase == 'none'
        end
      end

      set_data(open_methods: open_methods, api_methods: api_methods, rest_api_details: rest_api, stage_details: stage)

      if open_methods.count > 0
        fail(message: "REST API [#{api_name}] on deployment [#{stage_name}] has one or more methods that can be invoked by anyone", resource_id: "#{api_name}:#{stage_name}")
      else
        pass(message: "All methods in REST API [#{api_name}] on deployment [#{stage_name}] has authorization set", resource_id: "#{api_name}:#{stage_name}")
      end

    end

  end
end

