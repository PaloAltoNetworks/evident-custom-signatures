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
# Sample ESP signature to pull GuardDuty findings
# 
# As GuardDuty in't included in SecurityAudit role as of Feb 2018,
# Please add/attach `AmazonGuardDutyReadOnlyAccess` to ESP role.  
#
# In order to work, this signature requires at minimum the following permissions:
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "AllowAllUsersToViewAndManageThisGroup",
#       "Effect": "Allow",
#       "Action": [
#         "guardduty:ListDetectors",
#         "guardduty:GetFindings",
#         "guardduty:ListFindings"
#       ],
#       "Resource": "*"
#     }
#   ]
# }
# 
# Default Conditions:
# - FAIL: for each GuardDuty findings

#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:finding]
end

def perform(aws)
  findings = gd_get_findings(aws, nil)

  findings.each do | finding |

    finding_id = finding[:id]
    set_data(finding: finding)
    info(message: "testing", resource_id: finding_id)
  end
end

###################################################################################
## Pull guard duty findings
## if resource_id is nil, all findings will be returned
## If resource_id is not nil, only findings related to the resource_id is returned
###################################################################################
def gd_get_findings(aws,resource_id)
  output = []
  detector_ids = aws.guard_duty.list_detectors[:detector_ids]

  detector_ids.each do | detector_id |
    next_token = nil

    while next_token != "end"

      resp = aws.guard_duty.list_findings({detector_id: detector_id, max_results: 50, next_token: next_token})

      if resp[:next_token] and resp[:next_token] != ""
        next_token = resp[:next_token]
      else
        next_token = "end"
      end

      finding_ids = resp[:finding_ids]
      findings = aws.guard_duty.get_findings({detector_id: detector_id, finding_ids: finding_ids})[:findings]


      findings.each do | finding |
        output.push(finding) if resource_id == nil or JSON.dump(finding[:resource]).include?(resource_id)
      end
    end
  end

  return output
end