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
# Check for ELBs with SSL vulnerable to Diffie Hellman Key Exchange attacks
# 
# Default Conditions:
# - PASS: ELB is not vulnerable to Diffie Hellman Key Exchange attacks (https://weakdh.org)
# - FAIL: ELB IS vulnerable to Diffie Hellman Key Exchange attacks  (https://weakdh.org)
# 
# More info: https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf


configure do |c|
    c.deep_inspection   = [:load_balancer_name, :load_balancer_dns_name, :load_balancer_listener, :vulnerable_ciphers, :load_balancer, :ssl_policy]
    c.unique_identifier = [:load_balancer_name]
end

def perform(aws)
    aws.elb.describe_load_balancers.load_balancer_descriptions.each do |load_balancer|
        begin
            load_balancer_name = load_balancer[:load_balancer_name]
            load_balancer_dns_name = load_balancer[:dns_name]
        
            load_balancer[:listener_descriptions].each do |elb_listener|
                load_balancer_listener = elb_listener[:listener]
                load_balancer_port = load_balancer_listener[:load_balancer_port]
                load_balancer_protocol = load_balancer_listener[:protocol]
            
                if (load_balancer_protocol == "HTTPS")
                  failed_attributes = []
                  load_balancer_policy_names = elb_listener[:policy_names]
                  policy = aws.elb.describe_load_balancer_policies(load_balancer_name: load_balancer_name, policy_names: load_balancer_policy_names)
                  ssl_policy = policy[:policy_descriptions]
                  policy[:policy_descriptions].each do |description|
                    
                    description[:policy_attribute_descriptions].each do |attribute|
                      attribute_name = attribute[:attribute_name]
                      attribute_value = attribute[:attribute_value]

                      if (attribute_name =~ /^DHE.*$/) 
                        if attribute_value.downcase == 'true'
                            failed_attributes << attribute_name
                        end
                      end
                      
                    end
                  end

                  set_data(load_balancer_name: load_balancer_name, load_balancer_dns_name: load_balancer_dns_name, load_balancer_listener: load_balancer_listener, vulnerable_ciphers: failed_attributes, load_balancer: load_balancer, ssl_policy: ssl_policy)
                  if failed_attributes.empty?
                    pass(message: "Load Balancer #{load_balancer_name} is not vulnerable to Diffie Hellman Key Exchange attacks", resource_id: load_balancer_name)
                  else
                    fail(message: "Load Balancer #{load_balancer_name} is vulnerable to Diffie Hellman Key Exchange attacks", resource_id: load_balancer_name)
                  end
                
                end
            end
        rescue StandardError => e
            set_data(load_balancer_name: load_balancer_name, load_balancer_listener: load_balancer_listener)
            error(messages: "Error on Load Balancer #{load_balancer_name}", resource_id: load_balancer_name)
        end
    end

end

