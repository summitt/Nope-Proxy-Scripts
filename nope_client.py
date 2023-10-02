############################################
### This file is to be used with the Nope
### server. ./nope-server/server.py
### By default this just echos back the data
### that is sent. 
###########################################
import base64
import httplib

def formatOnly(input,isC2S):
	data = serverDecode(input)
	return bytearray(input)

def serverDecode(data):

	b64=base64.urlsafe_b64encode(data)
	conn = httplib.HTTPConnection('127.0.0.1:1337')
	conn.request("GET", "/?data={}".format(b64))
	resp = conn.getresponse()
	if resp.status == 200:
		b64_data = resp.read()
		data = base64.urlsafe_b64decode(b64_data)
		return data

	return data

