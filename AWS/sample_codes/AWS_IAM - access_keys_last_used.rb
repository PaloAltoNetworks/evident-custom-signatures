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
# Check when a key for an IAM user was last used and fail if used within the last hour
#
# John Martinez (john@evident.io)
#

configure do |c|
    c.deep_inspection   = [:user_name, :access_key_id, :last_used_date, :last_used_region, :elapsed_hours, :user]
    c.unique_identifier = [:user_name]
    c.valid_regions = [:us_east_1]
    c.display_as = :global
end

def perform(aws)

    aws.iam.list_users.users.each do |user|

        user_name = user[:user_name]
        user_id = user[:user_id]
        user_arn = user[:arn]

        access_keys = aws.iam.list_access_keys(user_name: user_name)

        if access_keys.access_key_metadata.length > 0
            access_keys.access_key_metadata.each do |access_key|
                access_key_id = access_key[:access_key_id]

                key_last_used = aws.iam.get_access_key_last_used(access_key_id: access_key_id)

                last_used = key_last_used[:access_key_last_used]
                last_used_date = last_used[:last_used_date]
                last_used_region = last_used[:region]

                if last_used_date.nil?
                    set_data(user_name: user_name, access_key_id: access_key_id, last_used_date: last_used_date, last_used_region: last_used_region, user: user)
                    warn(message: "User's (#{user_name}) access key has never been used", resource_id: user_name)
                else
                    now = Time.now
                    used = last_used_date
                    hours = ((now - used) / 3600).to_i
                    
                    set_data(user_name: user_name, access_key_id: access_key_id, last_used_date: last_used_date, last_used_region: last_used_region, elapsed_hours: hours, user: user)
                    if (hours <= 0) 
                        fail(message: "User's (#{user_name}) access key was used within the last hour", resource_id: user_name)
                    elsif (hours > 0 && hours <=24)
                        warn(message: "User's (#{user_name}) access key was used within the last 24 hours", resource_id: user_name)
                    else
                        pass(message: "User's (#{user_name}) access key was used more than 24 hours ago", resource_id: user_name)
                    end
                end
                
            end
        else
            set_data(user_name: user_name)
            pass(message: "User #{user_name} has no access key", resource_id: user_name)
        end

    end

end
