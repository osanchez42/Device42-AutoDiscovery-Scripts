"""
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

##############################################
# queries active directory for each computer
# adds device and ip to device42 appliance via REST APIs
#
#   Requires:
#       powershell
#       ironpython
#       .net 4
#
#   to run:
#       ipy.exe ad-sample.py
#   v2.2, Updated: 02-08-2014
##############################################

import os.path
import requests
from requests.auth import HTTPBasicAuth
import clr
import System
import math
import ssl
import functools
clr.AddReference("System.DirectoryServices")
clr.AddReference('System.Management.Automation')

from System.Management.Automation import RunspaceInvoke
# +---------------------------------------------------------------------------

# create a runspace to run shell commands from
RUNSPACE = RunspaceInvoke()

API_DEVICE_URL = BASE_URL + '/api/device/'
API_IP_URL = BASE_URL + '/api/ip/'

BASE_URL = 'https://your-url-here'  # make sure to NOT to end in /
USER = 'put-your-user-name-here'
PASSWORD = 'put-your-password-here'

DRY_RUN = False  # do not post just print the request that will be sent
DEBUG = True

old_init = ssl.SSLSocket.__init__
@functools.wraps(old_init)
def init_with_tls1(self, *args, **kwargs):
    kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1
    old_init(self, *args, **kwargs)


ssl.SSLSocket.__init__ = init_with_tls1


def post(url, params):
    """http post with basic-auth params is dict like object"""
    try:

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        if DRY_RUN:
            print(url, headers, params)
        else:
            if DEBUG:
                print('---REQUEST---')
                print(url)
                print(headers)
                print(params)

            req = requests.post(url, data=params, headers=headers, auth=HTTPBasicAuth(USER, PASSWORD))

            if DEBUG:
                print('---RESPONSE---')
                print(req.status_code)
                print(req.text)

    except Exception as err:
        print(err)


def get_computers():
    """Enumerates ALL computer objects in AD"""
    searcher = System.DirectoryServices.DirectorySearcher()
    searcher.SearchRoot = System.DirectoryServices.DirectoryEntry()
    searcher.Filter = "(objectCategory=computer)"
    searcher.PropertiesToLoad.Add("name")
    return sorted([a for item in searcher.FindAll() for a in item.Properties['name']])


def get_servers():
    """Enumerates ALL Servers objects in AD"""
    searcher = System.DirectoryServices.DirectorySearcher()
    searcher.SearchRoot = System.DirectoryServices.DirectoryEntry()
    searcher.Filter = "(&(objectCategory=computer)(OperatingSystem=Windows*Server*))"
    searcher.PropertiesToLoad.Add("name")
    return sorted([a for item in searcher.FindAll() for a in item.Properties['name']])


def get_fromfile():
    """Enumerates Computer Names in a text file Create a text file and enter
    the names of each computer. One computer name per line. Supply the path
    to the text file when prompted.
    """
    while True:
        filename = input('Enter the path for the text file: ')
        if filename:
            if not os.path.exists(filename):
                print("file not exists or insufficient permissions '%s'" % filename)
            elif not os.path.isfile(filename):
                print("not a file, may be a dir '%s'" % filename)
            else:
                f = open(filename)
                try:
                    computers = [line.strip() for line in f]
                finally:
                    f.close()
                return sorted(computers)


def get_frommanualentry():
    """'SingleEntry' - Enumerates Computer from user input"""
    while True:
        c = input('Enter Computer Name or IP: ')
        if c:
            return [c]


def wmi(query):
    """create list of dict from result of wmi query"""
    return [dict([(prop.Name, prop.Value) for prop in psobj.Properties])
        for psobj in RUNSPACE.Invoke(query)]


def wmi_1(query):
    a = wmi(query)
    if a:
        return a[0]
    else:
        return {}


def to_ascii(s):
    """remove non-ascii characters"""
    if isinstance(s, str):
        return s.encode('ascii', 'ignore')
    else:
        return str(s)


def closest_memory_assumption(v):
    if v < 512:
        v = 128 * math.ceil(v / 128.0)
    elif v < 1024:
        v = 256 * math.ceil(v / 256.0)
    elif v < 4096:
        v = 512 * math.ceil(v / 512.0)
    elif v < 8192:
        v = 1024 * math.ceil(v / 1024.0)
    else:
        v = 2048 * math.ceil(v / 2048.0)
    return int(v)


def main():
    banner = """\

+----------------------------------------------------+
| Domain Admin rights are required to enumerate information |
+----------------------------------------------------+
    """
    print(banner)

    menu = """\
Which computer resources would you like to run auto-discovery on?
    [1] All Domain Computers
    [2] All Domain Servers
    [3] Computer names from a File
    [4] Choose a Computer manually
    """
    while True:
        resp = input(menu)
        if resp == '1':
            computers = get_computers()
            break
        elif resp == '2':
            computers = get_servers()
            break
        elif resp == '3':
            computers = get_fromfile()
            break
        elif resp == '4':
            computers = get_frommanualentry()
            break

    if not computers:
        print("ERROR: No computer found")
    else:
        for c in computers:
            try:
                computer_system = wmi_1("Get-WmiObject Win32_ComputerSystem -Comp %s" % c)
                operating_system = wmi_1("Get-WmiObject Win32_OperatingSystem -Comp %s" % c)
                bios = wmi_1("Get-WmiObject Win32_BIOS -Comp %s" % c)
                mem = closest_memory_assumption(int(computer_system.get('TotalPhysicalMemory')) / 1047552)
                dev_name = to_ascii(computer_system.get('Name')).lower()
                device = {
                    'name': dev_name,
                    'memory': mem
                }
                if 'Caption' in operating_system:
                    device.update({'os': to_ascii(operating_system.get('Caption'))})
                    if 'CSDVersion' in operating_system:
                        device.update({'osver': to_ascii(operating_system.get('CSDVersion'))})
                    if 'Manufacturer' in operating_system:
                        device.update({'osmanufacturer': to_ascii(operating_system.get('Manufacturer'))})
                    if 'SerialNumber' in operating_system:
                        device.update({'osserial': to_ascii(operating_system.get('SerialNumber'))})
                    if 'Version' in operating_system:
                        device.update({'osverno': to_ascii(operating_system.get('Version'))})
                manufacturer = ''
                for mftr in ['VMware, Inc.', 'Bochs', 'KVM', 'QEMU', 'Microsoft Corporation', 'Xen']:
                    if mftr == to_ascii(computer_system.get('Manufacturer')).strip():
                        manufacturer = 'virtual'
                        device.update({'manufacturer': 'vmware', })
                        break
                if manufacturer != 'virtual':
                    device.update({
                        'manufacturer': to_ascii(computer_system.get('Manufacturer')).strip(),
                        'hardware': to_ascii(computer_system.get('Model')).strip(),
                        'serial_no': to_ascii(bios.get('SerialNumber')).strip(),
                        })

                cpucount = 0
                cpuspeed = None
                cpucores = None

                for cpu in wmi("Get-WmiObject Win32_Processor -Comp %s" % c):
                    cpucount += 1

                    try:
                        cpuspeed = cpu.get('MaxClockSpeed')
                        cpucores = cpu.get('NumberOfCores')
                    except Exception as e:
                        print(e)
                        continue

                if cpucount > 0:
                    device.update({
                        'cpucount': cpucount,
                        'cpupower': cpuspeed,
                        'cpucore':  cpucores,
                        })

                post(API_DEVICE_URL, device)

                for ntwk in wmi("Get-WmiObject Win32_NetworkAdapterConfiguration -Comp %s | where{$_.IPEnabled -eq \"True\"}" % c):
                    for ipaddr in ntwk.get('IPAddress'):
                        ip = {
                            'ipaddress': ipaddr,
                            'macaddress': ntwk.get('MACAddress'),
                            'tag': ntwk.get('Description'),
                            'device': dev_name,
                        }
                        try:
                            post(API_IP_URL, ip)
                        except Exception as e:
                            print('Exception occured trying to upload info for IP: %s' % ipaddr)
                            print(e)
            except Exception as err:
                print('failed for machine', c, str(err))


if __name__ == "__main__":
    main()
