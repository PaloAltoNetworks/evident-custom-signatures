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
# Check for API Gateway for unused Rest API 
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
# - PASS: RestAPI has one or more deployment
# - WARN: RestAPI does not have any deployment, but recently created
# - FAIL: RestAPI does not have any deployment

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # process recently created API differently as they may not have
  # any deployment yet
  # 
  # Specify the number of days before API is deemed as unused
  days_recently_created: 30
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:name , :id, :descriptions, :created_date, :deployments]
end

def perform(aws)
  # Get available APIs
  rest_apis = aws.api_gateway.get_rest_apis[:items]

  rest_apis.each do | rest_api |
    api_id = rest_api[:id]
    api_name = rest_api[:name]

    set_data(rest_api, created_date: rest_api[:created_date])
    deployments = aws.api_gateway.get_deployments(rest_api_id: api_id)[:items]
    
    if deployments.count < 1
      # Check if Rest API is recently created
      if ((Time.now - rest_api[:created_date])/3600/24).to_i > @options[:days_recently_created]
        fail(message: "REST API #{api_name} does not have any deployment", resource_id: api_id)
      else
        warn(message: "REST API #{api_name} was created recently (#{rest_api[:created_date]}) and does not have any deployments", resource_id: api_name)
      end
    else
      set_data(deployments: deployments)
      pass(message: "REST API #{api_name} has one or more deployments", resource_id: api_id)
      next
    end


  end
end

