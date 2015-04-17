#
# Check for buckets with no polcy attached
# Buckets are regional, so valid_regions must be set to one region only
# John Martinez <john@evident.io>
#
configure do |c|
    c.deep_inspection = [:bucket_name, :policy]
    c.valid_regions = [:us_east_1]
    c.unique_identifier = [:bucket_name]
end

def perform(aws)
    
    aws.s3.list_buckets[:buckets].each do |bucket|
        
        begin
            name   = bucket[:name]
            policy = aws.s3.get_bucket_policy(bucket: name)
            set_data(bucket_name: name, policy: policy, bucket: bucket)
            pass(message: "Bucket policy is set on bucket #{name}", resource_id: name)
        rescue StandardError => e
            fail(message: "Bucket #{name} does not have a policy.", resource_id: name, errors: e.message)

        end

    end

    
end
