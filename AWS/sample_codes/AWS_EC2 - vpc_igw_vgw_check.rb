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
# Check for VPCs which are attached to both IGWs and VGWs
# 
# Default Conditions:
# - PASS: N/A
# - FAIL: VPC has IGW and VGW
#

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:vpc_id ]
end

def perform(aws)
  
  vpc_list = {}
  # should filter this by state
  aws.ec2.describe_internet_gateways[:internet_gateways].each do | igw |
    if igw.attachments.length>0 && igw.attachments[0].state = "attached"
        vpc_list[igw.attachments[0].vpc_id] = {
            attached_igw_id: igw.internet_gateway_id,
            attached_igw_tags: igw.tags
        }
    end
      
  end
  
  
  invalid_vpc_list = {}
  aws.ec2.describe_vpn_gateways[:vpn_gateways].each do | vgw |
    if vgw.vpc_attachments.length > 0 && vgw.vpc_attachments[0].state = "attached"
        
        if vpc_list.include?(vgw.vpc_attachments[0].vpc_id)
            invalid_vpc_id = vgw.vpc_attachments[0].vpc_id
            invalid_vpc_list[invalid_vpc_id] = {
                attached_igw_id: vpc_list[invalid_vpc_id].attached_igw_id,
                attached_igw_tags: vpc_list[invalid_vpc_id].attached_igw_tags,
                attached_vgw_id: vgw.vpc_attachments[0].vpc_id,
                attached_vgw_tags: vgw.tags
            }
        end
    end
      
  end
  
  invalid_vpc_list.each do | vpc |
      set_data(vpc[1])
      fail(message: "VPC is attached to an internet gateway and a vpn gateway", resource_id: vpc[0], vpc_details: vpc[1])
  end
end