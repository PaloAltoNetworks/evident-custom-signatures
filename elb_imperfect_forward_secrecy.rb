## elb_dhe_check.rb 
## Description:
## Checks for ELBs using Diffie Hellman  (https://weakdh.org)
## Reports SSL Ciphers in the SSL Negotiation Policy of an ELB that support DHE_EXPORT
## More info: https://forums.aws.amazon.com/ann.jspa?annID=3061

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
                    pass(message: "Load Balancer #{load_balancer_name} is not vulnerable to LogJam", resource_id: load_balancer_name)
                  else
                    fail(message: "Load Balancer #{load_balancer_name} permits DHE_EXPORT ciphers and is vulnerable to LogJam", resource_id: load_balancer_name)
                  end
                
                end
            end
        rescue StandardError => e
            set_data(load_balancer_name: load_balancer_name, load_balancer_listener: load_balancer_listener)
            error(messages: "Error on Load Balancer #{load_balancer_name}", resource_id: load_balancer_name)
        end
    end

end

