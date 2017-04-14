##
## iam_access_keys_last_used.rb - John Martinez (john@evident.io)
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
##
## Description:
## Check when a key for an IAM user was last used and fail if used within the last hour
##

configure do |c|
    c.deep_inspection   = [:user_name, :access_key_id, :last_used_date, :last_used_region, :elapsed_hours, :user]
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
                    warn(message: "Access key has never been used", resource_id: access_key_id)
                else
                    now = Time.now
                    used = last_used_date
                    hours = ((now - used) / 3600).to_i
                    
                    set_data(user_name: user_name, access_key_id: access_key_id, last_used_date: last_used_date, last_used_region: last_used_region, elapsed_hours: hours, user: user)
                    if (hours <= 0) 
                        fail(message: "Access key was used within the last hour", resource_id: access_key_id)
                    elsif (hours > 0 && hours <=24)
                        warn(message: "Access key was used within the last 24 hours", resource_id: access_key_id)
                    else
                        pass(message: "Access key was used more than 24 hours ago", resource_id: access_key_id)
                    end
                end
                
            end
        end

    end

end
