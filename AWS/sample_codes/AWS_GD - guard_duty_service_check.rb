# Copyright (c) 2013, 2014, 2015, 2016, 2017, 2018. Evident.io (Evident). All Rights Reserved. 
# 
#   Evident.io shall retain all ownership of all right, title and interest in and to 
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"), 
#   including (a) all information and technology capable of general application to Evident.io's
#   customers; and (b) any works created by Evident.io prior to its commencement of any
#   Services for Customer.
# 
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services, 
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to 
#   use, copy, configure and translate any Deliverable solely for internal business operations
#   of the Customer as they relate to the Evident.io platform and products, and always
#   subject to Evident.io's underlying intellectual property rights.
# 
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, 
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF 
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF EVIDENT.IO HAS BEEN HAS BEEN
#   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 
#   THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS". 
#   EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
#   OR MODIFICATIONS.
# 
# Description:
#
# Ensure that Amazon GuardDuty service is currently enabled in order to protect your AWS
# environment and infrastructure against security threats.
#
# Default Conditions:
#
# - PASS: if one or more enabled GuardDuty detectors are found
# - WARN: if only disabled GuardDuty detectors found
# - FAIL: if no GuardDuty detectors are found
#
# Remediation (using awscli):
#
# aws guardduty create-detector --region <region> --enable
#

configure do |c|
  # Guard Duty supported regions:
  # * https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_regions.html
  #
  # Examples:
  # 
  # Comment out this option to check ALL regions (default)..
  # #c.valid_regions = [] 
  #
  # Check the N. Virginia region..
  # c.valid_regions = [:us_east_1]
  #
  # Check the N. Virginia, Oregon and Tokyo regions..
  # c.valid_regions = [:us_east_1, :us_west_2, :ap_northeast_1]
  #
  #c.valid_regions = [:us_east_1]
  c.deep_inspection = [:detectors]
end

def perform(aws)

  region       = aws.region
  detector_ids = get_detectors(aws)

  if detector_ids.empty?
    fail(message: "No GuardDuty detectors found in region #{region}.", resource_id: "Amazon GuardDuty")
    return
  end

  enabled_detectors  = []
  disabled_detectors = []

  detector_ids.each do | detector |
    status = aws.guard_duty.get_detector({ detector_id: detector })[:status]
    if status == "ENABLED"
      enabled_detectors.push(detector)
    else
      disabled_detectors.push(detector)
    end
  end

  detectors = {
    enabled_detectors: enabled_detectors,
    disabled_detectors: disabled_detectors
  }

  set_data(detectors: detectors)

  if enabled_detectors.length > 0
    pass(message: "GuardDuty detectors found in region #{region}.", resource_id: "Amazon GuardDuty")
  else
    warn(message: "No enabled GuardDuty detectors found in region #{region}.", resource_id: "Amazon GuardDuty")
  end
end

# GuardDuty supports only one detector resource per AWS account per region (as of February 2018).
#
def get_detectors(aws)

  next_token   = "start"
  max_results  = 1
  detector_ids = []

  while next_token != '' && next_token != nil
    if next_token == "start"
      resp = aws.guard_duty.list_detectors({ max_results: max_results })
    else
      resp = aws.guard_duty.list_detectors({ max_results: max_results, next_token: next_token })
    end

    next_token = resp[:next_token]
    detector_ids.push(resp[:detector_ids])
  end

  return detector_ids.flatten
end
