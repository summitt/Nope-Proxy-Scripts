#####################################################################
### This script can be used to unmask and decode web socket traffic
### using the Nope proxy : https://github.com/summitt/Burp-Non-HTTP-Extension
####################################################################
import sys
import subprocess
import json
import base64
import struct
import os
import httplib

def mangle(input, isC2S):
	if isC2S:
		if len(input) > 1 and (input[0] == 0x82 or input[0] == 0x02):
			### Unmask data. Only client to server is masked
			input = getUnmaskedDataFrame(input)
	return input



def preIntercept(input,isC2S):
	if len(input) == 0:
		return input
	elif len(input) > 1 and (input[0] == 0x82 or input[0] == 0x02):
		return getFullWebSocketPayload(input)

	else:
		return input

def postIntercept(input, isC2S):
	if len(input) == 0:
		return input
	elif len(input) > 1 and (input.find(b"[SOME PATTERN HERE]") != -1):
		return convertToWebSocket(input)
	else:
		return input

def formatOnly(input,isC2S):
	if input[0] == 0x82 or input[0] == 0x02:
		pbuf =  serverDecode(getFullWebSocketPayload(input))
		return bytearray(pbuf)
	else:
		return input


###############################################
##### WebSocket Encoding and Decoding
###############################################

def getUnmaskedDataFrame(wsData):
	payload = getFullWebSocketPayload(wsData)
	return convertToWebSocket(payload)

def getFullWebSocketPayload(wsData):
	payload=b''
	for frame in getFrames(wsData):
		payload = payload + getPayload(frame)

	return payload

def isFinal(wsData):
	return 0x80 & wsData[0] == 0x80

def isMasked(wsData):
	return 0x80 & wsData[1] == 0x80

def getLength(wsData):
	if wsData[1] & 0x7F == 126:
		len= struct.unpack('>H', wsData[2:4])
		return len[0]
	else:
		return wsData[1] & 0x7F

def getMask(wsData):
	if getLength(wsData) >= 126:
		mask = wsData[4:8]
	else:
		mask = wsData[2:6]
	return mask

def getPaylaodOffset(wsData):
	offset=2
	if isMasked(wsData):
		offset = offset + 4
	if getLength(wsData) > 126:
		offset = offset + 2
	return offset

def getPayload(wsData):
	payloadSize = getLength(wsData)
	payloadOffsetStart = getPaylaodOffset(wsData)
	payloadOffsetEnd=payloadOffsetStart+payloadSize
	payload = wsData[payloadOffsetStart:payloadOffsetEnd]
	if isMasked(wsData):
		mask = getMask(wsData)
		return xor(payload, mask)
	else:
		return bytearray(payload)

def getFrames(wsData):
	tmp = wsData
	frames = []
	while True:
		if isFinal(tmp):
			frames.append(tmp)
			break;
		else:
			payloadSize = getLength(tmp)
			payloadOffsetStart = getPaylaodOffset(wsData)
			payloadOffsetEnd=payloadOffsetStart+payloadSize
			frame = tmp[0:payloadOffsetEnd]
			frames.append(frame)
			tmp=tmp[payloadOffsetEnd:]

	return frames

def convertToWebSocket(payload):
	limit = 512
	chunked = list(chunks(payload, limit))

	wsBytes=b''
	for i in range(len(chunked)):
		chunk = chunked[i]

		isLast = i == len(chunked) -1
		payloadSize = len(chunk)
		if isLast and i==0:
			wsBytes = wsBytes + b'\x82'  # Final Byte
		elif isLast:
			wsBytes = wsBytes + b'\x80'  # Final Byte
		elif i == 0:
			wsBytes = wsBytes + b'\x02'  # Fragment
		else:
			wsBytes = wsBytes + b'\x00'  # Continued

		if payloadSize < 126:
			wsBytes = wsBytes + struct.pack("B",payloadSize)
		else:
			wsBytes = wsBytes + b'\x7E' + struct.pack(">H", payloadSize)

		wsBytes = wsBytes + chunk

	return bytearray(wsBytes)

def xor(data,mask):
	chunked = chunks(data,4)
	output=[]
	for subset in list(chunked):
		for i in range(4):
			if i < len(subset):
				output.append(subset[i] ^ mask[i])
	return bytearray(output)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

