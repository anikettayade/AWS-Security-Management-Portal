# import different modules required for the application
from flask import Flask, render_template, redirect, url_for, request, session, g, make_response
import sqlite3
import boto3
import sys
import os
import S3andSSH
import bcrypt
from functools import wraps, update_wrapper
from datetime import datetime
import CloudTrailandAMI
from flask import Flask
from flask_mail import Mail, Message
import validators
import logging
import logging.handlers 

username = ""
app = Flask(__name__)
app.database = "final.db"
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 60
app.config["CACHE_TYPE"] = "null"

############################################### MAIL SERVER SETUP #############################################################################

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '**************@gmail.com' # put your email id
app.config['MAIL_PASSWORD'] = '**********'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

#list that holds the credetnials
credentials  = list ()
############################################### FOR NO CACHE PROBLEM ##########################################################################

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = 'no-store, no-cache, \
        must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return update_wrapper(no_cache, view)
###############################################################################################################################################


############################################### CLOUDTRAIL COMPLETE ##########################################################################
@app.route('/cloudtrail')
@nocache
def scan_cloudtrail():
	if session['loggedIn'] == True:
		print "\n************** CLOUDTRAIL SCAN ****************"
		credentials = session['credentials']
		list_size= len(credentials)
		no_of_scan = list_size/3
		compliant= 0
		nocompliant= 0
		nocloudtrail= 0
		username = session['username'] 
		account_no = 1
		if list_size>=3:
			for n in range (0,list_size,3):
				print "\n\nSCANNING CLOUDTRAIL FOR ACCOUNT NO = "+str(account_no)
				account_no += 1
				value = exp2.connect_cloudtrail(credentials[n],credentials[n+1], credentials[n+2])
				if value == True:
					compliant += 1
                		elif value == False:
					nocompliant += 1
				elif value == "No CloudTrail":
					nocloudtrail +=1
			if compliant == no_of_scan:
				message = "COMPLIANT"
                        	return render_template('cloudtrailscan.html',msg=message)
			else :
				message = "NOT COMPLIANT"
                        	return render_template('cloudtrailscan.html',msg=message)
		else:
			message = "Database is not filled properly"
                        return render_template('cloudtrailscan.html ',msg=message)
        else:
                error= "You are not logged in. Try again"
                return render_template('login.html', error=error)
######################################################## CLOUDTRAIL COMPLETE #################################################################

###################################################### CLOUDTRAIL REMEDIATION #################################################################

@app.route('/remediate_cloudtrail')
@nocache
def remediate_cloudtrail():
        if session['loggedIn'] == True:
                print "\n************** CLOUDTRAIL REMEDIATION ****************"
                credentials = session['credentials']
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                nocompliant= 0
                nobucket= 0
                username = session['username']
                account_no = 1
                if list_size>=3:
                        for n in range (0,list_size,3):
                                print "\n\nREMEDIATING STARTED FOR ACCOUNT NO = "+str(account_no)
                                account_no += 1
				value = exp2.remediate_cloudtrail(credentials[n],credentials[n+1], credentials[n+2])
                                if value == True:
                                        compliant += 1
                        if compliant == no_of_scan:
                                message = "COMPLIANT"
                                return render_template('cloudtrailscan.html',msg=message)
                        else :
                                message = "NOT COMPLIANT -(Check logs)"
                                return render_template('cloudtrailscan.html',msg=message)
                else:
                        message = "Check Database for errors or No Input provided"
                        return render_template('cloudtrailscan.html',msg=message)
        else:
                error= "You are not logged in. Try again"
                return render_template('login.html', error=error)

###################################################### CLOUDTRAIL REMEDIATION ###############################################################

########################################## AMI IMAGE SCAN ID COMPLETE ########################################################################
@app.route('/AMI_image', methods = ['GET', 'POST'])
@nocache
def scan_AMI():
	if session['loggedIn'] == True:
		credentials = session['credentials']
		username = session['username']
                print "\n ************** AMI IMAGE ID SCAN ****************"
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                nocompliant= 0
                account_no = 1
		image_id = request.form['AMI']
                if  request.method == 'POST':
			if list_size>=3 :
				image_id = request.form['AMI']
				session['AMI_Image'] = image_id
				for n in range (0,list_size,3):
					print "\n\nSCANNING AMI IMAGE ID FOR ACCOUNT NO = "+str(account_no)
                                	account_no += 1
					value = exp2.scan_ami(credentials[n],credentials[n+1], credentials[n+2], image_id)
                                	if value == True:
                                        	compliant +=1
                        	if compliant == no_of_scan:
                                	message = "COMPLIANT"
                                	return render_template('amiidscan.html',msg=message)
                        	else :
                                	message = "Not COMPLIANT"
                                	return render_template('amiidscan.html',msg=message)
                else:
                        message = "Check Database for errors or No Input provided"
                        return render_template('amiidscan.html',msg=message)
        else:
                error= "You are not logged in. Try again"
                return render_template('login.html', error=error)
########################################  AMI SCAN COMPLETE  ############################################################

#####################################################  AMI REMEDATION  ############################################################

@app.route('/remediate_ami')
@nocache
def remediate_ami():
        if session['loggedIn'] == True:
                print "\n************** AMI IMAGE REMEDIATION ****************"
                credentials = session['credentials']
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                username = session['username']
                account_no = 1
		amilist = list()
                if list_size>=3:
                        for n in range (0,list_size,3):
                                print "\n\nREMEDIATING STARTED FOR ACCOUNT NO = "+str(account_no)
                                account_no += 1
                                value = exp2.scan_ami(credentials[n],credentials[n+1], credentials[n+2], session['AMI_Image'])
                                if value == True:
                                                compliant +=1
				else:
					amilist.append(value)
                        if compliant != no_of_scan:
				print amilist
				msg = Message('Alert', sender = 'andya22005@gmail.com', recipients = ['%s',session['username'] ])
				msg.body = "There are instances launched that does not match the Image_ID = %s\n\nThe List of Accounts and instances that are not compliant = \n %s"%(session['AMI_Image'],amilist)
				mail.send(msg)
                                message = "EMAIL SENT"
                                return render_template('amiidscan.html',msg=message)
                        else :
                                message = "COMPLIANT"
                                return render_template('amiidscan.html',msg=message)





########################################  SSH SCAN COMPLETE ############################################################
@app.route('/SSH')
@nocache
def scan_ssh():
	if session['loggedIn'] == True:
                username = session['username']
                print "\n ************** SSH SCAN ****************"
		credentials = session['credentials']
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                nocompliant= 0
                nocloudtrail= 0
                account_no = 1
		grouplist = list()
                if list_size>=3 :
			for n in range (0,list_size,3):
                                        print "\n\nSCANNING SECURITY GROUP FOR ACCOUNT NO = " + str(account_no)
                                        account_no += 1
                                        value = exp1.scan_ssh(credentials[n],credentials[n+1], credentials[n+2])
					if value == True:
                                                compliant +=1
					else:
						grouplist.append(value)			
			if compliant == no_of_scan:
                                        message = "COMPLIANT"                        
  				        return render_template('sshscan.html',msg=message)
			else :
                                        message = "Not COMPLIANT"
                                        return render_template('sshscan.html',msg=grouplist)
                else:
                        message = "Check Database for errors or No Input provided"
                        return render_template('scan.html',msg=message)
        else:
                error= "You are not logged in. Try again"
                return render_template('login.html', error=error)
########################################################## COMPLETED SSH SCAN ################################################################

##########################################################  SSH REMEDIATION ################################################################

@app.route('/remediate_ssh', methods = ['GET', 'POST'])
@nocache
def remediate_ssh():
        if session['loggedIn'] == True:
                print "\n************** SSH PORT REMEDIATION ****************"
                credentials = session['credentials']
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                username = session['username']
                account_no = 1
                group_id = request.form['GROUP_NAME']
		ip_address = request.form['IP_ADDRESS']
		ipv4 = ip_address.split('/')
		check_ip_address = validators.ip_address.ipv4(str(ipv4[0]))
                if  request.method == 'POST':
			if not check_ip_address:
				print "Please enter correct IP ADDRESS"
		         #       return render_template('sshscan.html', error=error)
			else:
	                       	if list_size>=3 :
	 	                        for n in range (0,list_size,3):
		                                print "\n\nREMEDIATING STARTED FOR ACCOUNT NO = "+str(account_no)
                		                account_no += 1

                                		value = exp1.remediate_ssh(credentials[n],credentials[n+1], credentials[n+2], ip_address,group_id)
                                		if value == True:
                                                	compliant +=1

					message = "COMPLIANT"
                                        return render_template('sshscan.html',msg=message)

				else:
		                        message = "Check Database for errors or No Input provided"
                		        return render_template('sshscan.html',msg=message)

 		else:
			error = "Method POST not used"
			return render_template('sshscan.html', error=error)                               		
                                       	 	

	else:
                error= "You are not logged in. Try again"
                return render_template('login.html', error=error)

#		return render_template('sshscan.html', error=error)


########################################################## COMPLETED #######################################################################

###################################################  S3 Encryption COMPLETE ##################################################################
@app.route('/s3encryption')
@nocache
def scan_s3encryption():
	if session['loggedIn'] == True:
                print "\n ************** S3 ENCRYPTION SCAN ****************"
		credentials = session['credentials']
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                nocompliant= 0
                nobucket= 0
                username = session['username']
                account_no = 1
                if list_size>=3:
                        for n in range (0,list_size,3):
                                print "\n\nSCANNING S3BUCKET ENCRYPTION FOR ACCOUNT NO = "+str(account_no)
                                account_no += 1
                                value = exp1.connect_to_s3(credentials[n],credentials[n+1], credentials[n+2])
                                if value == True:
                                        compliant += 1
                                elif value == False:
                                        nocompliant += 1
                                elif value == "No Bucket":
                                        nobucket +=1
                        if compliant == no_of_scan:
                                message = "COMPLIANT"
                                return render_template('s3encryptionscan.html',msg=message)
			else :
				message = "NotCOMPLIANT"
                                return render_template('s3encryptionscan.html',msg=message)
		else:
                        message = "Check Database for errors or No Input provided"
                        return render_template('s3encryptionscan.html',msg=message)
	else:
		error= "You are not logged in. Try again"
                return render_template('login.html', error=error)
###########################################################################################################################################

######################################################### REMEDIATE S3 COMPLETE ############################################################
@app.route('/remediates3')
@nocache
def remediates3():
        if session['loggedIn'] == True:
                print "\n ************** S3 ENCRYPTION SCAN ****************"
                credentials = session['credentials']
                list_size= len(credentials)
                no_of_scan = list_size/3
                compliant= 0
                nocompliant= 0
                nobucket= 0
                username = session['username']
                account_no = 1
                if list_size>=3:
                        for n in range (0,list_size,3):
                                print "\n\nREMEDIATING S3BUCKET ENCRYPTION FOR ACCOUNT NO = "+str(account_no)
                                account_no += 1
				value = exp1.remediate_s3(credentials[n],credentials[n+1], credentials[n+2])
                                if value == True:
                                        compliant += 1
                                elif value == "No Bucket":
                                        nobucket +=1
                        if compliant == no_of_scan:
                                message = "COMPLIANT"
                                return render_template('s3encryptionscan.html',msg=message)
                        else :
                                message = "NotCOMPLIANT"
                                return render_template('s3encryptionscan.html',msg=message)
                else:
                        message = "Check Database for errors or No Input provided"
                        return render_template('s3encryptionscan.html',msg=message)
        else:
                error= "You are not logged in. Try again"
                return render_template('login.html', error=error)
#########################################################################################################################################

############################################## INDEX #############################################

@app.route('/index')
@nocache
def index():
#    if 'secretkey' in session:
	if session['loggedIn'] == True:
        	username = session['username']
		print "\n ***************** IN INDEX ************************"
		return render_template('dashboard.html')
	else :
		error= "You are not logged in. Try again"
                return render_template('login.html', error=error)
 #   return "You are not logged in <br><a href = '/login'></b>" + \
  #      "click here to log in</b></a>"
############################################## INDEX #############################################


#################################################### LOGIN PAGE WORKING ######################################################################

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if (request.form['username'] == None  or
                request.form['password']==None ):
            error = 'Invalid Credentials. Please try again.'
        else:
	    g.db = connect_db()
            cur = g.db.execute('select * from credentials where emailid == "%s"'%request.form['username'])           
            name = cur.fetchall()
	    n  =  len(name[0])
	    m = 2
	    while name[0][m]!=None and m<n:
		credentials.append(name[0][m])
		m+=1
	    session['credentials'] = credentials
	    print "\n Updated the LIST with Credential Details"
	    account_no= len(credentials)
	    account_no = account_no/3
            session['account_no'] = account_no
	    if name :
		pwd = name[0][1]
		if  bcrypt.checkpw(request.form['password'], pwd):
			cnt = 3						
			session['loggedIn'] = True
			session['username'] = request.form['username']
                        print "\n SUCCESSFUL LOGIN by USER " + str(session['username'])
                        print "\n The number of accounts that we are going to monitor is = " + str (account_no)
			print "\n Redirecting to the index function"
			g.db.close() 					
			return redirect(url_for('index'))
            else:
		g.db.close()
		error= "Invalid Credentials. Try again"
                return render_template('login.html', error=error)
	error= "Invalid Credentials. Try again"
    return render_template('login.html', error=error)

#################################################### LOGIN PAGE WORKING ######################################################################

def connect_db():
	return sqlite3.connect(app.database)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session['loggedIn']= False
    session.pop('loggedIn', None)
    handler.close()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.secret_key = 'fw;nfgkergn;ergcdsdbbvr'
        
    app.run(debug=True)
