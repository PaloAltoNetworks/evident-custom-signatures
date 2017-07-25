# PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
# Copyright (c) 2017 Evident.io, Inc., All Rights Reserved
#
# Description:
# Import Flagged resources from Trusted Advisor as ESP Alerts
# 
# This custom signature requires additional permission:
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "Stmt1495740401000",
#       "Effect": "Allow",
#       "Action": [
#         "support:*",
#       ],
#       "Resource": [
#         "*"
#       ]
#     }
#   ]
# }
# 
# Default Conditions:
# - PASS: If flagged resource has "ok" or "not_available" status
# - WARN: If flagged resource has "warning" status
# - FAIL: If flagged resource has "error"
#


#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = { 
  # List the Trusted advisor's check ID that you want to import
  # on "check_ids"
  # Here are the valid IDs => Names as of 5/2017
  #
  # "Qch7DwouX1" =>  "Low Utilization Amazon EC2 Instances"
  # "hjLMh88uM8" =>  "Idle Load Balancers"
  # "DAvU99Dc4C" =>  "Underutilized Amazon EBS Volumes"
  # "Z4AUBRNSmz" =>  "Unassociated Elastic IP Addresses"
  # "HCP4007jGY" =>  "Security Groups - Specific Ports Unrestricted"
  # "1iG5NDGVre" =>  "Security Groups - Unrestricted Access"
  # "zXCkfM1nI3" =>  "IAM Use"
  # "Pfx0RwqBli" =>  "Amazon S3 Bucket Permissions"
  # "7DAFEmoDos" =>  "MFA on Root Account"
  # "Yw2K9puPzl" =>  "IAM Password Policy"
  # "nNauJisYIT" =>  "Amazon RDS Security Group Access Risk"
  # "H7IgTzjTYb" =>  "Amazon EBS Snapshots"
  # "wuy7G1zxql" =>  "Amazon EC2 Availability Zone Balance"
  # "iqdCTZKCUp" =>  "Load Balancer Optimization "
  # "S45wrEXrLz" =>  "VPN Tunnel Redundancy"
  # "ZRxQlPsb6c" =>  "High Utilization Amazon EC2 Instances"
  # "8CNsSllI5v" =>  "Auto Scaling Group Resources"
  # "opQPADkZvH" =>  "Amazon RDS Backups"
  # "f2iK5R6Dep" =>  "Amazon RDS Multi-AZ"
  # "CLOG40CDO8" =>  "Auto Scaling Group Health Check"
  # "eW7HH0l7J9" =>  "Service Limits"
  # "BueAdJ7NrP" =>  "Amazon S3 Bucket Logging"
  # "PPkZrjsH2q" =>  "Amazon EBS Provisioned IOPS (SSD) Volume Attachment Configuration"
  # "tfg86AVHAZ" =>  "Large Number of Rules in an EC2 Security Group"
  # "j3DFqYTe29" =>  "Large Number of EC2 Security Group Rules Applied to an Instance"
  # "Ti39halfu8" =>  "Amazon RDS Idle DB Instances"
  # "B913Ef6fb4" =>  "Amazon Route 53 Alias Resource Record Sets"
  # "cF171Db240" =>  "Amazon Route 53 Name Server Delegations"
  # "C056F80cR3" =>  "Amazon Route 53 High TTL Resource Record Sets"
  # "k3J2hns32g" =>  "Overutilized Amazon EBS Magnetic Volumes"
  # "796d6f3D83" =>  "CloudFront Content Delivery Optimization"
  # "51fC20e7I2" =>  "Amazon Route 53 Latency Resource Record Sets"
  # "c9D319e7sG" =>  "Amazon Route 53 MX Resource Record Sets and Sender Policy Framework"
  # "b73EEdD790" =>  "Amazon Route 53 Failover Resource Record Sets"
  # "Cb877eB72b" =>  "Amazon Route 53 Deleted Health Checks"
  # "vjafUGJ9H0" =>  "AWS CloudTrail Logging"
  # "1MoPEMsKx6" =>  "Amazon EC2 Reserved Instances Optimization"
  # "a2sEc6ILx" =>   "ELB Listener Security"
  # "xSqX82fQu" =>   "ELB Security Groups"
  # "xdeXZKIUy" =>   "ELB Cross-Zone Load Balancing"
  # "7qGXsKIUw" =>   "ELB Connection Draining"
  # "N415c450f2" =>  "CloudFront Header Forwarding and Cache Hit Ratio"
  # "N425c450f2" =>  "CloudFront Custom SSL Certificates in the IAM Certificate Store"
  # "N430c450f2" =>  "CloudFront SSL Certificate on the Origin Server"
  # "Bh2xRR2FGH" =>  "Amazon EC2 to EBS Throughput Optimization"
  # "N420c450f2" =>  "CloudFront Alternate Domain Names"
  # "DqdJqYeRm5" =>  "IAM Access Key Rotation"
  # "12Fnkpl8Y5" =>  "Exposed Access Keys"
  # "G31sQ1E9U" =>   "Underutilized Amazon Redshift Clusters"
  # "1e93e4c0b5" =>  "Amazon EC2 Reserved Instance Lease Expiration"
  # "R365s2Qddf" =>  "Amazon S3 Bucket Versioning"
  # "0t121N1Ty3" =>  "AWS Direct Connect Connection Redundancy"
  # "8M012Ph3U5" =>  "AWS Direct Connect Location Redundancy"
  # "4g3Nt5M1Th" =>  "AWS Direct Connect Virtual Interface Redundancy"
  # "xuy7H1avtl" =>  "Amazon Aurora DB Instance Accessibility"
  # "Wnwm9Il5bG" =>  "PV Driver Version for EC2 Windows Instances"
  # "V77iOLlBqz" =>  "EC2Config Service for EC2 Windows Instances"
  #
  # You can also set check_ids: ['all']
  # WARNING: Each individual check needs to be called separately.
  #          Setting the value to 'all' generates ~60 additional API call to AWS Support
  check_ids: ['eW7HH0l7J9','Qch7DwouX1'],


  # The alert status of Trusted Resource Check to be passed on as ESP alert 
  # Valid options: ok, warning, error, not_available
  # Mappings (TA -> ESP):
  # - ok or not_available    -> PASS
  # - warning                -> WARN
  # - error                  -> FAIL
  #
  # If you set the value to just ['error'], 
  # This custom signature will process the 'error' alert from TA
  resource_status: ['warning','error'],

  # A lot of TA check IDs does not return ok alert on monitored resources
  # By default, when there is no flagged resources returned by the Trusted Advisor,
  # no ESP alert is generated
  #
  # Setting this option to true will cause ESP to generate a PASS alert
  # when Trusted advisor returns no flagged resources 
  pass_on_no_TA_alerts: false
}


configure do |c|
  # By default, a custom signature is executed against all region. 
  # Trusted advisor is regionless.  
  # So, let's restrict the region to just us-east-1
  c.valid_regions     = [:us_east_1]
  # override the region displayed in the alert from us-east-1 to global
  c.display_as        = :global
end


def perform(aws)
  metadata = get_ta_metadata(aws)

  @options[:check_ids].each do | check_id |
    if metadata.key?(check_id)
      result = aws.support.describe_trusted_advisor_check_result(language: 'en', check_id: check_id)[:result]

      if result[:flagged_resources].count < 1 and @options[:pass_on_no_TA_alerts]
        pass(message: "No Flagged resources for check ID #{check_id}", resource_id: check_id)
        next
      end

      result[:flagged_resources].each do | resource |
        if @options[:resource_status].include?(resource[:status])
          send_alert(metadata[check_id], resource)
        end
      end
    end
  end

end

def send_alert(check_info,resource)
  info = {
    check_name: check_info[:name],
    check_category: check_info[:category],
    status: resource[:status],
    region: resource[:region],
    suppressed: resource[:is_suppressed],
    fields: check_info[:metadata]
  }

  data = {}
  i = 0
  while i < check_info[:metadata].count do 
    data[check_info[:metadata][i]] = resource[:metadata][i]
    i += 1
  end

  if resource[:status] == 'ok' or resource[:status] == 'not_available'
    pass(resource_id: resource[:resource_id], check_info: info, data: data) 
  elsif resource[:status] == 'warning'
    warn(resource_id: resource[:resource_id], check_info: info, data: data)
  elsif resource[:status] == 'error'
    fail(resource_id: resource[:resource_id], check_info: info, data: data)
  end
    
    

end


def get_ta_metadata(aws)
  metadata = {}
  checks = aws.support.describe_trusted_advisor_checks(language: 'en').checks
  checks.each do | check |
    metadata[check[:id]] = check
  end

  return metadata
end
