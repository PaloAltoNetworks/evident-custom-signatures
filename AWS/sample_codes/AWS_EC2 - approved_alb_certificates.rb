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
# Ensures that ALB HTTPS listeners use approved certificates
# 
# Default Conditions:
# - PASS: ALB does not have listener with unapproved SSL certificate
# - FAIL: One of ALB HTTPS listener uses unapproved certificate


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {
  # List of approved certificate ARNs. Case sensitive
  # For IAM server certificate, use the certificate name
  # For ACN, use the certificate ID
  #
  # For example, to whitelist the following certificates:
  # - IAM server certificate: arn:aws:iam::123456789012:server-certificate/myServerCert
  # - ACM certificate: arn:aws:acm:us-west-2:123456789012:certificate/abcdefgh-1234-5678-abcd-0000abcdefgh
  #
  # approved_certificate_arns: [
  #   "arn:aws:iam::123456789012:server-certificate/myServerCert",
  #   "arn:aws:acm:us-west-2:123456789012:certificate/abcdefgh-1234-5678-abcd-0000abcdefgh"
  # ],
  approved_certificate_arns: [
    "arn:aws:iam::019841101606:server-certificate/mycert"
  ],

}

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:load_balancer_name, :load_balancer_dns_name, :offending_listeners, :listeners, :options, :tags]
end

def perform(aws)
  aws.elbv2.describe_load_balancers[:load_balancers].each do | lb |

    # Only care about ALB
    next if lb[:type] != "application"

    lb_name = lb[:load_balancer_name]
    lb_arn = lb[:load_balancer_arn]

    offending_listeners = []

    listeners = aws.elbv2.describe_listeners(load_balancer_arn: lb_arn)[:listeners]
    listeners.each do | listener |
      next if listener[:protocol] != "HTTPS"

      offending_cert_found = false
      listener[:certificates].each do | cert |
        if @options[:approved_certificate_arns].include?(cert[:certificate_arn]) == false
          offending_cert_found = true 
        end
      end

      offending_listeners.push(listener) if offending_cert_found
    end

    set_data(lb)
    set_data(offending_listeners: offending_listeners, listeners: listeners, options: @options)
    if offending_listeners.count > 0
      fail(message: "Load Balancer #{lb_name} has one or more listener with unapproved SSL certificate", resource_id: lb_name)
    else
      pass(message: "Load Balancer #{lb_name} does not have listener with unapproved SSL certificate", resource_id: lb_name)
    end
  end
end

