
import logging
import random
from radiusconstants import *
from radiusmessage import *

class Error(Exception): pass
class NoResponse(Error): pass
class SocketError(NoResponse): pass

import socket

valid_healthcheck_types = ["shallow","deep"]

def perform_healthcheck(server=socket.gethostname(),port=1812,type="shallow"):

    sock = socket.socket(socket.AF_INET, # Internet                           
                         socket.SOCK_DGRAM) # UDP

    addr = (server, port)

    secret='healthcheck'
    healthcheck = RadiusMessage()
    healthcheck.identifier = random.randint(1,255)
    healthcheck.makeHealthCheckRequest("shallow")
    healthcheck.secret=secret


    msg = healthcheck.getUDPDatagram()

    retries = 1
    timeout = 5
    try:
        for i in range(0,retries):
            sock.sendto(msg, addr)
            response = None
            resp_datagram = ""

            t = select( [sock,],[],[],timeout)
            if len(t[0]) > 0:
                resp_datagram = sock.recv(4096)            
                response = RadiusResponse(datagram=resp_datagram,secret=secret)

                if not healthcheck.checkDatagram(resp_datagram):
                    print "response doesn't pass validation"
                    return False

                #print response
            else:
                continue

            if response.code == RADIUS_ACCT_STATUS and \
                   response.getSpecificAttr(RADIUS_PROXY_STATE) == "success":
                return True
            else:
                print "healthcheck failed code=%d [%s]" % (response.code, response.getSpecificAttr(RADIUS_PROXY_STATE))
                return False


    except socket.error,x: # SocketError
        try: self.closesocket()
        except: pass
        raise SocketError(x)

    return False

