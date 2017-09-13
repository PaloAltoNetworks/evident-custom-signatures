#
# Copyright 2013, 2014, 2015, 2016, 2017. Evident.io (Evident). All Rights Reserved. 
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
# Check for unused Access Keys
# Check for Access Keys' last used
#
# Default Condition:
# - PASS: Access key has been used in x days
# - PASS: Access key is inactive
# - WARN: Access key was created x days ago and have not been used
# - FAIL: Access key was used, and haven't been used in x days
#
# Remediations:
# - Deactivate or delete access key
#

#    ______     ___     ____  _____   ________   _____     ______   
#  .' ___  |  .'   `.  |_   \|_   _| |_   __  | |_   _|  .' ___  |  
# / .'   \_| /  .-.  \   |   \ | |     | |_ \_|   | |   / .'   \_|  
# | |        | |   | |   | |\ \| |     |  _|      | |   | |   ____  
# \ `.___.'\ \  `-'  /  _| |_\   |_   _| |_      _| |_  \ `.___]  | 
#  `.____ .'  `.___.'  |_____|\____| |_____|    |_____|  `._____.'  
# Configurable options                                                                  
@options = {  
  # Access key last used (in days)
  last_used_days: 90
}


#    ______   ____  ____   ________     ______   ___  ____     ______   
#  .' ___  | |_   ||   _| |_   __  |  .' ___  | |_  ||_  _|  .' ____ \  
# / .'   \_|   | |__| |     | |_ \_| / .'   \_|   | |_/ /    | (___ \_| 
# | |          |  __  |     |  _| _  | |          |  __'.     _.____`.  
# \ `.___.'\  _| |  | |_   _| |__/ | \ `.___.'\  _| |  \ \_  | \____) | 
#  `.____ .' |____||____| |________|  `.____ .' |____||____|  \______.' 
                                                                      
# deep inspection attribute will be included in each alert
configure do |c|
  c.deep_inspection   = [:user_name, :access_key_id, :create_date, :age_days, :access_key_last_used]
  c.unique_identifier = [:user_name]
  c.valid_regions = [:us_east_1]
  c.display_as = :global
end

def perform(aws)
  aws.iam.list_users.users.each do |user|
    user_name = user[:user_name]
    access_keys = aws.iam.list_access_keys(user_name: user_name)

    access_keys.access_key_metadata.each do |access_key|
      access_key_id = access_key[:access_key_id]
      create_date = access_key[:create_date]
      status = access_key[:status]

      set_data(user_name: user_name, access_key_id: access_key_id, create_date: create_date)

      if status == "Inactive"
        pass(message: "Access key #{access_key_id} is inactive", resource_id: access_key_id)
        next
      end

      access_key_last_used = aws.iam.get_access_key_last_used(access_key_id: access_key_id)[:access_key_last_used][:last_used_date]

      if (access_key_last_used.nil? or access_key_last_used == "N/A")
        # key never been used. Throw warn alert if it has never been used for so long
        set_data(access_key_last_used: nil)
        if ((Time.now - create_date)/3600/24).to_i > @options[:last_used_days]
          warn(message: "Access Key #{access_key_id} was created more than #{@options[:last_used_days]} days ago and never been used", resource_id: access_key_id)
        else
          pass(message: "Access Key #{access_key_id} has never been used", resource_id: access_key_id)
        end
      else
        set_data(access_key_last_used: access_key_last_used)
        if ((Time.now - access_key_last_used)/3600/24).to_i > @options[:last_used_days]
          fail(message: "Access Key #{access_key_id} last used more than #{@options[:last_used_days]} days ago.", resource_id: access_key_id)
        else
          pass(message: "Access key #{access_key_id} last used in #{@options[:last_used_days]} days", resource_id: access_key_id)
        end
      end
    end
  end
end
