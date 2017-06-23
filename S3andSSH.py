import boto3
import sys
import os
import logging
import logging.handlers
from datetime import datetime



unsecured = list()
def connect_to_s3(region,accesskey,secretkey):	
	cnt =0
	cnt1 =0
	s1 = boto3.resource('s3', region_name= region, aws_access_key_id= accesskey, aws_secret_access_key= secretkey)
	s2 = boto3.client('s3', region_name= region, aws_access_key_id= accesskey, aws_secret_access_key= secretkey)
	bucketlist =  s2.list_buckets()
	bucketlist = bucketlist['Buckets']
	if bucketlist:
		bucketlist = bucketlist[0]['Name']
        	for bucket in s1.buckets.all():
                	if bucket:
				print bucket
                    		for obj in bucket.objects.filter():
                        		object = s1.Object(bucket.name,obj.key)
                        		if not object.server_side_encryption:
                                			cnt += 1
	else :
		cnt +=1
		print "No Bucket"
		return False
        if cnt == cnt1:
                print "All Keys are encrypted"
                return True
        else :
                print "All Keys are not  encrypted"
                return False


def remediate_s3(region,accesskey,secretkey):
        clientid = boto3.client("sts", region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
        account_id = clientid.get_caller_identity()["Account"]
        name = str(account_id)
        account_name = name.split('/')
        print "ACCOUNT ID  = " + str(name)

 	i = datetime.now()
        LOG_FILENAME = 'S3logs/S3Remediation%s-%s.log'%(str(name),i.strftime('%Y-%m-%d-%H-%M-%S'))
        my_logger = logging.getLogger('S3Remediation-%s'%str(name))
        my_logger.setLevel(logging.DEBUG)
        handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                               maxBytes=5000000,
                                               backupCount=5)
        my_logger.addHandler(handler)
	s1 = boto3.resource('s3', region_name= region, aws_access_key_id= accesskey, aws_secret_access_key= secretkey)
	print "\nREMEDIATION STARTED"
        s2 = boto3.client('s3', region_name= region, aws_access_key_id= accesskey, aws_secret_access_key= secretkey)
        bucketlist =  s2.list_buckets()
        bucketlist = bucketlist['Buckets']
	my_logger.debug("ACCOUNT ID  = %s"%str(name))
        if bucketlist: 
                bucketlist = bucketlist[0]['Name']
                for bucket in s1.buckets.all():
                        if bucket:
			    print bucket
			    for obj in bucket.objects.filter():
				object = s1.Object(bucket.name,obj.key)
				if not object.server_side_encryption:
					object.copy_from(CopySource = {'Bucket':bucket.name, 'Key':obj.key}, ServerSideEncryption='AES256')
					print "THE FILE WHICH WAS ENCRYPTED WITH AES256 = %s" + str (obj.key)
					my_logger.debug("%s THE FILE WHICH WAS ENCRYPTED WITH AES256 = %s"% (i.strftime('%Y-%m-%d-%H-%M-%S'),str(obj.key)))
	else:
		print "No Bucket"
		return "No Bucket"
	handler.close()
	return True
			
def scan_ssh(region,accesskey,secretkey):		
	grouplist = list()
	client1 = boto3.client("sts", aws_access_key_id=accesskey, aws_secret_access_key=secretkey)
        account_id = client1.get_caller_identity()["Account"]
	grouplist.append(account_id)
	ec2 = boto3.client('ec2', region_name= region, aws_access_key_id= accesskey, aws_secret_access_key= secretkey)
	print "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
	response = ec2.describe_security_groups()
	cnt = 0
	rule_cnt = 0
	for m in response['SecurityGroups']:	
		list1 = m['IpPermissions']
		print "New Trial"
		len1 = len(list1)
		if 'tcp' in str(m['IpPermissions'])  or '-1' in str(m['IpPermissions']):
			print "There exits SSH settings"
			for i in range(len1):
				if str(m['IpPermissions'][i]['IpProtocol']) == 'tcp' or str(m['IpPermissions'][i]['IpProtocol']) == '-1':			
					print "Rules checking"
	                	        if "FromPort" not in str(m['IpPermissions'][i]):
        	                	        if "0.0.0.0/0" in str(m['IpPermissions'][i]['IpRanges']):
                	                	        print "test2"
                        	                	cnt +=1
                                	        	print "Not Compliant SecurityGroup = %s"%str(m['GroupName']) + " Group ID = %s"%m['GroupId']
							rule_cnt +=1
                        		elif int(m['IpPermissions'][i]['FromPort'])<=22 and  int(m['IpPermissions'][i]['ToPort'])>=22 :
                                	
                                		if "0.0.0.0/0" in str(m['IpPermissions'][i]['IpRanges']):
                                        		cnt +=1; print "test3"
                                        		print "Not Compliant SecurityGroup = %s"%str(m['GroupName'])  + " Group ID = %s"%m['GroupId']
							rule_cnt +=1
			if rule_cnt > 0 :
				print "The number of rules not compliant in group = %s is = %s"%(str(m['GroupName']),str(rule_cnt))
				grouplist.append(m['GroupName'])
				rule_cnt = 0
        if cnt == 0:
                print "ALL SECURITY GROUPS ARE COMPLAINT"
                return True
        else :
                print grouplist
                return grouplist


def remediate_ssh(region,accesskey,secretkey,ip_address,group_name):

        clientid = boto3.client("sts", region_name = region,aws_access_key_id = accesskey, aws_secret_access_key = secretkey)
        account_id = clientid.get_caller_identity()["Account"]
        name = str(account_id)
        account_name = name.split('/')
        print "ACCOUNT ID  = " + str(name)

        t = datetime.now()
        LOG_FILENAME = 'SecurityGrplogs/SSHRemediation%s-%s.log'%(str(name),t.strftime('%Y-%m-%d-%H-%M-%S'))
        my_logger = logging.getLogger('SSHRemediation-%s'%str(name))
        my_logger.setLevel(logging.DEBUG)
        handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                               maxBytes=5000000,
                                               backupCount=5)
        my_logger.addHandler(handler)
        ec2 = boto3.client('ec2', region_name= region, aws_access_key_id= accesskey, aws_secret_access_key= secretkey)
	response = ec2.describe_security_groups()
	my_logger.debug("ACCOUNT ID  = %s"%str(name))
	if group_name:
		print "Doing changes for only one specific group = %s"%str(group_name)
		for m in response['SecurityGroups']:	
			if str(group_name) == str(m['GroupName']):
				list1 = m['IpPermissions']
				print "Remediating the Group = %s"%str(m['GroupName'])
				len1 = len(list1)
				if 'tcp' in str(m['IpPermissions'])  or '-1' in str(m['IpPermissions']):
					print "Checking the group inbound rules"
					for i in range(len1):
						if str(m['IpPermissions'][i]['IpProtocol']) == 'tcp' or str(m['IpPermissions'][i]['IpProtocol']) == '-1':			
							print "Checking whether the protocol is TCP or All Traffic"
	                	        		if "FromPort" not in str(m['IpPermissions'][i]):
        	                	        		if "0.0.0.0/0" in str(m['IpPermissions'][i]['IpRanges']):
                	                	        		print "All traffic is allowed"
                        	                			ec2.revoke_security_group_ingress(IpProtocol="-1", CidrIp="0.0.0.0/0", GroupId =m['GroupId'])
									print "Revoke the %s rule which allowed all traffic" % str(group_name)
									my_logger.debug("%s Revoke the %s rule which allowed all traffic"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(group_name)))
									ec2.authorize_security_group_ingress(IpProtocol="tcp",CidrIp=str(ip_address),FromPort=22,ToPort=22, GroupId =m['GroupId'])
                        						print "Changed the SSH settings"
									my_logger.debug("%s THE SECURITY GROUP TCP SETTIGNS FOR PORT 22 CHANGED TO ALLOW = IP %s"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(ip_address)))
									
                        				elif int(m['IpPermissions'][i]['FromPort'])<=22 and  int(m['IpPermissions'][i]['ToPort'])>=22 :                                	
                                				if "0.0.0.0/0" in str(m['IpPermissions'][i]['IpRanges']):
									print "Port Range allows SSH access" 
	                                       				ec2.revoke_security_group_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0",FromPort=m['IpPermissions'][i]['FromPort'], ToPort=m['IpPermissions'][i]['ToPort'], GroupId =m['GroupId'])
									my_logger.debug("%s Revoke the %s rule which allowed all traffic"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(group_name)))
									print "Revoke the security group = %s"% str(group_name)
									ec2.authorize_security_group_ingress(IpProtocol="tcp",CidrIp=str(ip_address),FromPort=22,ToPort=22, GroupId =m['GroupId'])
                        						print "Changed the SSH settings"
									my_logger.debug("%s THE SECURITY GROUP TCP SETTIGNS FOR PORT 22 CHANGED TO ALLOW = IP %s"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(ip_address)))																	
	else:
		        print "Doing changes for all security groups"
			for m in response['SecurityGroups']:			
				list1 = m['IpPermissions']
				len1 = len(list1)
				if 'tcp' in str(m['IpPermissions'])  or '-1' in str(m['IpPermissions']):
					print "There exits SSH settings for all groups"
					for i in range(len1):
						if str(m['IpPermissions'][i]['IpProtocol']) == 'tcp' or str(m['IpPermissions'][i]['IpProtocol']) == '-1':			
							print "Rules checking for all groups"
	                	        		if "FromPort" not in str(m['IpPermissions'][i]):
        	                	        		if "0.0.0.0/0" in str(m['IpPermissions'][i]['IpRanges']):
                	                	        		ec2.revoke_security_group_ingress(IpProtocol="-1", CidrIp="0.0.0.0/0", GroupId =m['GroupId'])
									print "All -groups Revoke the %s rule which allowed all traffic" % str(group_name)
									my_logger.debug("%s Revoke the %s rule which allowed all traffic"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(group_name)))
									ec2.authorize_security_group_ingress(IpProtocol="tcp",CidrIp=str(ip_address),FromPort=22,ToPort=22, GroupId =m['GroupId'])
                        						print "Changed the SSH settings"
									my_logger.debug("%s THE SECURITY GROUP TCP SETTIGNS FOR PORT 22 CHANGED TO ALLOW = IP %s"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(ip_address)))	
		                        		elif int(m['IpPermissions'][i]['FromPort'])<=22 and  int(m['IpPermissions'][i]['ToPort'])>=22 :                	
                                				if "0.0.0.0/0" in str(m['IpPermissions'][i]['IpRanges']):
									print "All Groups - Port Range allows SSH access" 
	                                       				ec2.revoke_security_group_ingress(IpProtocol="tcp", CidrIp="0.0.0.0/0",FromPort=m['IpPermissions'][i]['FromPort'], ToPort=m['IpPermissions'][i]['ToPort'], GroupId =m['GroupId'])
									print "Revoke the security group = %s"% str(group_name)
									my_logger.debug("%s Revoke the %s rule which allowed all traffic"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(group_name)))
									ec2.authorize_security_group_ingress(IpProtocol="tcp",CidrIp=str(ip_address),FromPort=22,ToPort=22, GroupId =m['GroupId'])
                        						print "Changed the SSH settings"                                        		
                                        				my_logger.debug("%s THE SECURITY GROUP TCP SETTIGNS FOR PORT 22 CHANGED TO ALLOW = IP %s"% (t.strftime('%Y-%m-%d-%H-%M-%S'),str(ip_address)))
	
	handler.close()
