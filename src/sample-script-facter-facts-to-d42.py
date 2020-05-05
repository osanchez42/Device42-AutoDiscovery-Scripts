"""

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

################################################################
# The script goes through the yaml fact files created by facter
# and populates device42 database with following info:
#device name, manufacturer, hardware model, serial #, os info, memory, cpucount and cpucores info
# IP address, interface name and mac address.
# Script tested with python 2.4
################################################################

import requests
from requests.auth import HTTPBasicAuth
import types
import os.path
import traceback
import sys
import glob
import math
#Device42 URL and credentials
BASE_URL='https://your-device42-url'  #Please make sure there is no / in the end

API_DEVICE_URL=BASE_URL+'/api/device/'   
API_IP_URL =BASE_URL+'/api/ip/'          

USER ='your-device42-user-name'
PASSWORD='your-device42-password-here'
DRY_RUN = False

# puppet config dir
puppetdir="/var/opt/lib/pe-puppet/yaml/node/"  #Change to reflect node directory with yaml fact files.


def post(url, params):
    """http post with basic-auth params is dict like object"""
    try:
        data= params
        headers = {
            'Content-Type' : 'application/x-www-form-urlencoded'
        }

        if DRY_RUN:
            print(url, headers, data)
        else:
            print('---REQUEST---', url)
            print(headers)
            print(data)

            req = requests.post(url, data=data, headers=headers, auth=HTTPBasicAuth(USER, PASSWORD))

            print('---RESPONSE---')
            print(req.status_code)
            print(req.text)
    except Exception as Err:
        print('-----EXCEPTION OCCURED-----')
        print(Err)

def to_ascii(s):
    """remove non-ascii characters"""
    if isinstance(s, str):
        return s.encode('ascii','ignore')
    else:
        return str(s)        
def closest_memory_assumption(v):
    if v < 512: v = 128 * math.ceil(v / 128.0)
    elif v < 1024: v = 256 * math.ceil(v / 256.0)
    elif v < 4096: v = 512 * math.ceil(v / 512.0)
    elif v < 8192: v = 1024 * math.ceil(v / 1024.0)
    else: v = 2048 * math.ceil(v / 2048.0)
    return int(v)     
for infile in glob.glob( os.path.join(puppetdir, '*yaml') ):       
    d = {}
           
    f = open(infile)
    print("---Going through fact file: %s" % infile)
    for line in f:
        if "--" not in line:

            line = line.strip().replace('"','')
            try:
                key, val = line.split(':',1)
                d[key] = val.strip()
            except: pass

    f.close()       
    device_name = to_ascii(d['clientcert'])  #using clientcert as the nodename here, you can change it to your liking.
    os = to_ascii(d.get('operatingsystem', None))
    osver = to_ascii(d.get('operatingsystemrelease', None))
    device = {
        'name' : device_name,}
        
    if os is not None: device.update({'os' : os,})
    if osver is not None: device.update({'osverno' :osver,})
    manufacturer = to_ascii(d.get('manufacturer', None)).strip()
    if manufacturer is not None:
        for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
            if mftr == manufacturer:
                manufacturer = 'virtual'
                device.update({ 'manufacturer' : 'vmware', })
                break    
        if manufacturer != 'virtual':
            hw =  to_ascii(d.get('productname', None))
            sn =  to_ascii(d.get('serialnumber', None))
            
            if hw is not None: device.update({
                    'manufacturer' :  manufacturer,
                    'hardware' : hw,
                    })
            if sn is not None: device.update({
                    'serial_no' : sn,
                }) 
    mem_b = d.get('memorysize',None).split(' ')[1]
    if mem_b is not None:
        if mem_b == 'MB':
            memory = closest_memory_assumption(int(float(d['memorysize'].split(' ')[0])))
        else: memory = closest_memory_assumption(int(float(d['memorysize'].split(' ')[0])*1024))
        device.update({'memory': memory,})
    cpucount = int(d.get('physicalprocessorcount', None))
    if cpucount is not None:
        if cpucount == 0: cpucount = 1
        cpucore = int(d.get('processorcount', None))
        device.update({    
        'cpucount': cpucount,
        'cpucore': cpucore,        
        })
    
    post(API_DEVICE_URL, device)
    interfaces =  d.get('interfaces',None).split(',')
    if interfaces is not None:
        for interface in interfaces:
            if not 'loopback' in interface.lower():
                ipkey = 'ipaddress'+'_'+interface.replace(' ','').lower()
                mackey  = 'macaddress'+'_'+interface.replace(' ','').lower()
                try: macaddress = d[mackey]
                except: macaddress = d.get('macaddress', None)
                ip = {
                    'ipaddress' : d.get(ipkey, None),
                    
                    'device' : device_name,
                    'tag': interface.replace('_', ' ')
                    }
                if macaddress is not None: ip.update({'macaddress' : macaddress,})
                if ip.get('ipaddress') is not None and ip.get('ipaddress') != '127.0.0.1': post(API_IP_URL, ip)

