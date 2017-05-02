#
# Ensure that the S3 bucket does not have static web hosting enabled
#
# PASS if S3 bucket does not have static web hosting enabled
# FAIL if S3 bucket has static web hosting enabled
#
#

configure do |c|
  c.deep_inspection = [:bucket_name, :region, :website_configuration]
  c.unique_identifier = [:bucket_name]
end


def perform(aws)
  aws.s3.list_buckets[:buckets].each do |bucket|
    bucket_name = bucket[:name]

    begin

      bucket_location = aws.s3.get_bucket_location(bucket: bucket_name).location_constraint

      # AWS may return "" for buckets in us-east-1 
      # if your S3 client's region is set to us-east-1  
      if bucket_location == ""
          next if aws.s3.config[:region] != "us-east-1"
      elsif bucket_location != aws.s3.config[:region]
          next
      end

      set_data(bucket_name: bucket_name, region: aws.s3.config[:region], website_configuration: nil )

      website_configuration = aws.s3.get_bucket_website(bucket: bucket_name)
      set_data(website_configuration: website_configuration)
  
      fail(message: "Bucket #{bucket_name} has website configuration enabled", resource_id: bucket_name)      

    rescue StandardError => e
      # Bucket doesn't have a policy set
      if e.message.include? "The specified bucket does not have a website configuration"
        pass(message: "Bucket #{bucket_name} doesn not have website configuration enabled", resource_id: bucket_name)
      else
        error(message: "Error in getting the website configuration configuration for bucket: #{bucket_name}.", resource_id: bucket_name, errors: e.message)
      end

    end

  end
end
