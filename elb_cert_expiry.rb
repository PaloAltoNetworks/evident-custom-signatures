##
## elb_cert_expiry.rb - John Martinez (john@evident.io)
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
##
## Description:
## Checks how close the SSL certificates assigned to the HTTPS listener of an
## Elastic Load Balancer is to expiring
##

configure do |c|
    c.deep_inspection   = [:load_balancer_name, :load_balancer_dns_name, :expiry_date, :load_balancer_listener]
    c.unique_identifier = [:load_balancer_name]
end

def perform(aws)
    

  aws.elb.describe_load_balancers.load_balancer_descriptions.each do |load_balancer|

    load_balancer_name = load_balancer[:load_balancer_name]
    load_balancer_dns_name = load_balancer[:dns_name]

    load_balancer[:listener_descriptions].each do |elb_listener|

      load_balancer_listener = elb_listener[:listener]
      load_balancer_port = load_balancer_listener[:load_balancer_port]
      load_balancer_protocol = load_balancer_listener[:protocol]

      if (load_balancer_protocol == "HTTPS")
        load_balancer_ssl_certificate_id = load_balancer_listener[:ssl_certificate_id]


        aws.iam.list_server_certificates.server_certificate_metadata_list.each do |cert|
          cert_server_certificate_name = cert[:server_certificate_name]
          cert_arn = cert[:arn]
          cert_expiration = cert[:expiration]

          if (cert_arn == load_balancer_ssl_certificate_id)
            now = Date.today
            expiry_date = cert_expiration.to_datetime
            days_left = (expiry_date - now).to_i - 1

            set_data(load_balancer_name: load_balancer_name, load_balancer_dns_name: load_balancer_dns_name, expiry_date: expiry_date, days_left: days_left, load_balancer_listener: load_balancer_listener)

            if (days_left < 0)
              fail(message: "SSL Certificate for ELB #{load_balancer_name} has expired", resource_id: load_balancer_name)
            elsif (days_left < 30)
              fail(message: "SSL Certificate for ELB #{load_balancer_name} expires in less than 30 days", resource_id: load_balancer_name)
            elsif (days_left > 30 && days_left < 90)
              warn(message: "SSL Certificate for ELB #{load_balancer_name} within 90 days", resource_id: load_balancer_name)
            elsif (days_left >=90)
              pass(message: "SSL Certificate for ELB #{load_balancer_name} won't expire for more than 90 days", resource_id: load_balancer_name)
            end
          end
        end

      end
    end
  end
end

