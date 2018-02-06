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
# Check ELB certificate's expiration
# 
# Default Conditions:
# - PASS: SSL certificate won't expire in 90 days
# - WARN: SSL certificate will be expired in 90 days
# - FAIL: SSL Certificate expired, or expiring in 30 days
#
# Resolution/Remediation:
# - Renew your certificate
# - Update ELB SSL certificate 
#   http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-update-ssl-cert.html
#

configure do |c|
    c.deep_inspection   = [:load_balancer_name, :load_balancer_dns_name, :expiry_date, :days_left, :load_balancer_listener]
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

