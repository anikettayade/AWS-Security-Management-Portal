import boto3
import sys
import os
import json
from flask import Flask
from flask_mail import Mail, Message
from datetime import datetime
 

trails = list()
def connect_cloudtrail(region,accesskey,secretkey):
	client = boto3.client('cloudtrail', region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
	trails = client.describe_trails()
	print "\nEXECUTING THE CLOUDTRAIL SCAN FUNCTION"
	cnt = 0
	t1= trails['trailList']
	if not t1: 
		print "\nCLOUDTRAIL IS NOT ENABLED FOR THIS ACCOUNT"
		return "No CloudTrail"
	print "THE NUMBER OF TRAIL_LIST PRESENT IN THIS ACCOUNT " + str (len (t1))
	l1 = dict()
	if t1:
		for n in range (len(t1)):
			print  "CHECKING CLOUDTRAIL = %s STORING THE LOGS IN THE S3 BUCKET = %s"%(str(t1[n]['Name']),str(t1[n]['S3BucketName']))
			l1 = client.get_trail_status(Name = t1[n]['TrailARN'])
			if l1['IsLogging']:
				print "\nTHE ABOVE CLOUDTRAIL IS LOGGING"
#				return True
			else :
				print "\nTHE ABOVE CLOUDTRAIL IS NOT LOGGING"
#				return False
				cnt += 1
		if cnt == 0:
			return True
		else:
			return False


def remediate_cloudtrail(region,accesskey,secretkey):
        client = boto3.client('cloudtrail', region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
        trails = client.describe_trails()
        t1= trails['trailList'] 
	i = datetime.now()
        clientid = boto3.client("sts", region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
        account_id = clientid.get_caller_identity()["Account"]
        name = str(account_id)
        account_name = name.split('/')
        print "ACCOUNT ID  = " + str(name)
        if not t1:
                print "\nSINCE NO CLOUDTRAIL IS PRESENT CURRENTLY IN THIS ACCOUNT - NEED TO CREATE NEW CLOUDTRAIL"
		client1 = boto3.client("sts", aws_access_key_id=accesskey, aws_secret_access_key=secretkey)
		account_id = client1.get_caller_identity()["Account"]
		s3 = boto3.resource('s3', region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
		bucketname = "anicloudtrailbucket"+ i.strftime('%Y-%m-%d-%H-%M-%S')
		bckt = s3.create_bucket(Bucket=bucketname, CreateBucketConfiguration={'LocationConstraint':region})		
		bucket_policy = bckt.Policy()
		print "\nCREATING BUCKET AND SETTING THE BUCKET POLICY TO ALLOW CLOUDTRAIL ACCESS IT"
		s3_permissions_policy = json.dumps({
 						"Statement": [{
        						"Sid": "cloudtrailcheckACL",
        						"Effect": "Allow",
							"Principal": {"Service": "cloudtrail.amazonaws.com"},
        						"Action": "s3:GetBucketAcl",
#        						"Resource":["arn:aws:s3:::anicloudtrailbucket"]
							"Resource":["arn:aws:s3:::%s"% bucketname]
    							} , {
					
         						"Sid": "AWSCloudTrailWrite",
            						"Effect": "Allow",
            						"Principal": {"Service": "cloudtrail.amazonaws.com"},
            						"Action": "s3:PutObject",
#            						"Resource":["arn:aws:s3:::anicloudtrailbucket/AWSLogs/%s/*" % account_id],
							"Resource":["arn:aws:s3:::%s/AWSLogs/%s/*" % (bucketname,account_id)],
            						"Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        						}]
						    })
		bucket_policy.put(Policy=s3_permissions_policy)		
		if bckt:
			print "\nCREATED BUCKET WITH APPROPRIATE POLICY"
#			response = client.create_trail(Name='CloudTrailLog',S3BucketName='anicloudtrailbucket')
			response = client.create_trail(Name='CloudTrailLog',S3BucketName=bucketname)
			if response:
				m = client.start_logging(Name='CloudTrailLog')
				if m:
					print "\nCREATED TRAIL AND ITS CURRENTLY LOGGING"
					return True

		return "Bucket Not Created"
        l1 = dict()
        if t1:
                for n in range (len(t1)):
#                        print t1[n]['S3BucketName']
                        l1 = client.get_trail_status(Name = t1[n]['TrailARN'])
                        if not l1['IsLogging']:
				print "THE CLOUDTRAIL == %s  [NOT LOGGING] "% str(t1[n]['Name'])
				client.start_logging(Name = t1[n]['TrailARN'])
				print "REMEDIATED"
	return True			

def scan_ami(region,accesskey,secretkey, image_id):
	ec2 = boto3.client('ec2', region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
	client = boto3.client("sts", region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
	account_id = client.get_caller_identity()["Account"]
	name = str(account_id)
	account_name = name.split('/')
	print "ACCOUNT ID  = " + str(name)
	paginator = ec2.get_paginator('describe_instances')
	ec2 = boto3.resource('ec2', region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
	cnt = 0
	cnt1 = 0
	amilist = list()
	amilist.append(account_id)
	for instance in ec2.instances.all():
        	print "The instance id = " + str(instance.id)
        	r=paginator.paginate(InstanceIds=[instance.id])
        	for n in r :
                	print n['Reservations'][0]['Instances'][0]['ImageId']
			cnt +=1
			if image_id == n['Reservations'][0]['Instances'][0]['ImageId']:
				cnt1 +=1
			else:
				amilist.append(instance.id)				
	print "The number of AMI images are compliant = " + str(cnt1) 
 	if cnt == cnt1:
		return True
	else:
		return amilist

