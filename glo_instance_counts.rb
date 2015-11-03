##
## glo_instance_counts.rb - John Martinez (john@evident.io)
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2015 Evident.io, Inc., All Rights Reserved
##
## Description:
## Give instance and node counts for the various services that support instances
##
configure do |c|
    c.deep_inspection   = [:ec2_instance_count, :rds_instance_count, :elasticache_node_count, :redshift_node_count, :emr_instance_count]
end

# Required perform method
def perform(aws)

    region = aws.region
    total_count = 0
    
    # count EC2 instances
    ec2_instance_count = aws.ec2.describe_instances.reservations.map(&:instances).count
    total_count += ec2_instance_count
    
    # count RDS DB instances
    rds_instance_count = aws.rds.describe_db_instances.db_instances.count
    total_count += rds_instance_count

    # count ElastiCache nodes
    elasticache_node_count = 0
    aws.ec.describe_cache_clusters.cache_clusters.each do |ec_cluster|
        elasticache_node_count += ec_cluster.cache_nodes.count
    end
    total_count += elasticache_node_count
    
    # count Redshift nodes
    redshift_node_count = 0
    aws.rs.describe_clusters.clusters.each do |rs_cluster|
        redshift_node_count += rs_cluster.cluster_nodes.count
    end
    total_count += redshift_node_count
    
    # count EMR instances
    emr_instance_count = 0
    emr_clusters = aws.emr.list_clusters.clusters
    if emr_clusters.count > 0
        emr_clusters.each do |emr_cluster|
            emr_cluster_id = emr_cluster.id
            emr_instance_count += aws.emr.list_instances(cluster_id: emr_cluster_id).instances.count
        end
    end
    
    set_data(ec2_instance_count: ec2_instance_count, rds_instance_count: rds_instance_count, elasticache_node_count: elasticache_node_count, redshift_node_count: redshift_node_count, emr_instance_count: emr_instance_count)

    warn(message: "Total instance counts in region #{aws.region}: #{total_count}", instance_count: total_count)

end

