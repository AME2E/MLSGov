import boto3

# Define the AWS regions where you want to terminate instances
regions = ["us-east-2", "us-west-2"]

protected_instanceid = "i-0da612750e3dfba26"
def shutdown_regions(regions):
    # Iterate through the specified regions
    for region in regions:
        ec2 = boto3.client("ec2", region_name=region)

        # Describe all running instances in the region
        response = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])

        # Extract instance IDs from the response
        instance_ids = []
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                instance_ids.append(instance["InstanceId"])
        if protected_instanceid in instance_ids:
            instance_ids.remove(protected_instanceid)
        if instance_ids:
            # Terminate the running instances
            try:
                ec2.terminate_instances(InstanceIds=instance_ids)
                print(f"Terminating instances in {region}: {', '.join(instance_ids)}")
            except Exception as e:
                print(e)
        else:
            print(f"No running instances found in {region}")


if __name__ == '__main__':
    shutdown_regions(regions)
