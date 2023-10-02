################################################
### You can use this generic flask server
### to add additional features to the Nope 
### Manger. 
### To start use generic_server.py 
### community script. nope_client.py
##############################################
from flask import Flask, request
import base64


app = Flask(__name__)

@app.route("/")
def decode():
    try:
        data = request.args.get('data')
        print(data)
        decoded = decode_data(data)
        # print so we know its doing something
        print(decoded)
        # just echo it back in this example
        data = base64.urlsafe_b64encode(decoded)
        return data
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        ## if we get anything in the client thats not a 200 
        ## the client with fail silently and proceed with 
        ## the original payload
        return "Error", 409

def decode_data(data):
    decoded_data=base64.urlsafe_b64decode(data)
    escaped_data=decoded_data.decode("unicode_escape")
    byteArray=b''
    for byte in escaped_data:
        tmp=bytes(byte,'utf-8')
        if len(tmp) > 1:
            byteArray = byteArray + struct.pack("B",tmp[1])
        else:
            byteArray = byteArray + tmp
    return byteArray



if __name__ == '__main__':
    app.run(debug=True, port=1337)
