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
# Check to see if EFS File Systems are encrypted
#
#
# Default Conditions:
# - PASS: EFS is encrypted
# - FAIL: EFS is not encrypted
#



#    ______   ____  ____   ________     ______   ___  ____     ______
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_|
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) |
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.'

# deep inspection attribute will be included in each alert
configure do |c|
    c.deep_inspection   = [:owner_id, :creation_toke, :file_system_id, :creation_time, :life_cycle_state, :name, :encrypted, :kms_key_id]
end

def perform(aws)

  begin
    file_systems = aws.elastic_filesystem.describe_file_systems[:file_systems]
    file_systems.each do | efs |
        set_data(efs)
        if efs[:encrypted]
            pass(message: "File system encrypted", resource_id: efs[:file_system_id])
        else
            fail(message: "File system not encrypted", resource_id: efs[:file_system_id])
        end
    end
  rescue StandardError => e
    if e.message.include?("Failed to open TCP connection to elasticfilesystem")
      info(message: "EFS service not available in this region")
    elsif e.message.include?("NoMethodError")
      error(message: "Please ensure that ESP role has permission proper permission")
    else
      error(message: e.message)
    end
  end
end
