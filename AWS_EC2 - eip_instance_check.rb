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
# Check for Elastic IP (EIP)
#
# This custom signature grabs the list of reserved EIP and see if any of it is attached to an instance
# 
# Default Conditions:
# - PASS: No EIP reserved
# - WARN: EIP reserved but not associated to any instance
# - FAIL: EIP reserved and attached to an instance
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # List EIP that you want to whitelist here
  # If EIP is listed in the whitelist and attached to an instance
  # instead of triggering FAIL alert, it triggers PASS alert
  #
  # Example: whitelisted_ips: ['54.54.54.54','53.53.53.53']
  whitelisted_ips: [],
}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:domain, :instance_id, :public_ip, :allocation_id, :association_id, :network_interface_id, :private_ip_address]
end

def perform(aws)
  eip_list = aws.ec2.describe_addresses[:addresses]

  if eip_list.count == 0
    pass(message: "No Elastic IP reserved in this region")
    return
  end
  
  eip_list.each do | eip |
    set_data(eip)

    if eip.key?("instance_id") and eip[:instance_id] != ""
      if @options[:whitelisted_ips].include?(eip[:public_ip])
        pass(message: "EIP is associated with instance #{eip[:instance_id]}. Alert set to pass due to whitelist", resource_id: eip[:public_ip], whitelist: @options[:whitelisted_ips])
      else
        fail(message: "EIP is associated with instance #{eip[:instance_id]}", resource_id: eip[:public_ip])
      end
    else
      warn(message: "EIP is reserved but not associated with any instance", resource_id: eip[:public_ip])
    end
  end
end

