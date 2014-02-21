#!/usr/bin/python2.7
import sys
import os
import socket
import subprocess
import libvirt
from operator import itemgetter
import logging
import logging.handlers
from xml.etree import ElementTree as ET
import os.path
import subprocess
import signal
import commands
from nova.network import linux_net
from nova import paths
from nova import utils
import novaclient.v1_1.client as nvclient
from oslo.config import cfg
import re

linux_net_opts = [
    cfg.MultiStrOpt('dhcpbridge_flagfile',
                    default=['/etc/nova/nova-dhcpbridge.conf'],
                    help='location of flagfiles for dhcpbridge'),
    cfg.StrOpt('networks_path',
               default=paths.state_path_def('networks'),
               help='Location to keep network config files'),
    cfg.StrOpt('public_interface',
               default='eth0',
               help='Interface for public IP addresses'),
    cfg.StrOpt('network_device_mtu',
               default=None,
               help='MTU setting for vlan'),
    cfg.StrOpt('dhcpbridge',
               default=paths.bindir_def('nova-dhcpbridge'),
               help='location of nova-dhcpbridge'),
    cfg.StrOpt('routing_source_ip',
               default='$my_ip',
               help='Public IP of network host'),
    cfg.IntOpt('dhcp_lease_time',
               default=120,
               help='Lifetime of a DHCP lease in seconds'),
    cfg.MultiStrOpt('dns_server',
                    default=[],
                    help='if set, uses specific dns server for dnsmasq. Can'
                         'be specified multiple times.'),
    cfg.BoolOpt('use_network_dns_servers',
                default=False,
                help='if set, uses the dns1 and dns2 from the network ref.'
                     'as dns servers.'),
    cfg.ListOpt('dmz_cidr',
               default=[],
               help='A list of dmz range that should be accepted'),
    cfg.MultiStrOpt('force_snat_range',
               default=[],
               help='Traffic to this range will always be snatted to the '
                    'fallback ip, even if it would normally be bridged out '
                    'of the node. Can be specified multiple times.'),
    cfg.StrOpt('dnsmasq_config_file',
               default='',
               help='Override the default dnsmasq settings with this file'),
    cfg.StrOpt('linuxnet_interface_driver',
               default='nova.network.linux_net.LinuxBridgeInterfaceDriver',
               help='Driver used to create ethernet devices.'),
    cfg.StrOpt('linuxnet_ovs_integration_bridge',
               default='br-int',
               help='Name of Open vSwitch bridge used with linuxnet'),
    cfg.BoolOpt('send_arp_for_ha',
                default=False,
                help='send gratuitous ARPs for HA setup'),
    cfg.IntOpt('send_arp_for_ha_count',
               default=3,
               help='send this many gratuitous ARPs for HA setup'),
    cfg.BoolOpt('use_single_default_gateway',
                default=False,
                help='Use single default gateway. Only first nic of vm will '
                     'get default gateway from dhcp server'),
    cfg.MultiStrOpt('forward_bridge_interface',
                    default=['all'],
                    help='An interface that bridges can forward to. If this '
                         'is set to all then all traffic will be forwarded. '
                         'Can be specified multiple times.'),
    cfg.StrOpt('metadata_host',
               default='$my_ip',
               help='the ip for the metadata api server'),
    cfg.IntOpt('metadata_port',
               default=8775,
               help='the port for the metadata api port'),
    cfg.BoolOpt('fake_network',
                default=False,
                help='If passed, use fake network devices and addresses'),
    ]


CONF = cfg.CONF
CONF.register_opts(linux_net_opts)
CONF.import_opt('host', 'nova.netconf')
CONF.import_opt('use_ipv6', 'nova.netconf')
CONF.import_opt('my_ip', 'nova.netconf')

CONF.set_override('lock_path','/var/lib/nova/tmp')

lockfile_path = "/tmp/"

# logging
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address = '/dev/log')
formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

# connection to kvm
conn = libvirt.open('qemu:///system')
if conn == None:
	log.error('Failed to open connection to the hypervisor. Exiting')
	sys.exit(1)


def attach_debug(instance_name, uuid):
	# socat tcp-l:54321,reuseaddr,fork file:${serial},nonblock,waitlock=/var/run/socat-pts.lock
	running_doms = conn.listDomainsID()

	log.error("looking for instance data: %s" % instance_name)

	for runningDomID in running_doms:
		runningDom = conn.lookupByID(runningDomID)
		if runningDom.name() == instance_name:
			phy_serial = find_serial_port_xml(ET.fromstring(runningDom.XMLDesc(0)))
			break

	port = get_port_num()
	lockfile = lockfile_path + runningDom.name() + ".lock"
	start_socat(lockfile, port, phy_serial)
	create_fw_rules(port)

	listen_port = get_ip_address() + ":" + str(port)
	update_metadata(uuid, listen_port)
	log.debug("Opened port " + str(port) + " for instance %s" % runningDom.name())

def detach_debug(instance_name):
	running_doms = conn.listDomainsID()
	for runningDomID in running_doms:
		runningDom = conn.lookupByID(runningDomID)
		if runningDom.name() == instance_name:
			pid = check_for_lockfile(instance_name) 
			if pid > 0:
				port = kill_socat(pid)
				log.error("removing firewall rules for port %s" % port)
				del_fw_rules(port)
			else:
				log.debug("couldn't find lockfile /tmp/" + runningDom.name()  + ".lock")
			break

def get_ip_address():
	intf = 'br-ex'
	intf_ip = commands.getoutput("ip address show dev " + intf).split()
	intf_ip = intf_ip[intf_ip.index('inet') + 1].split('/')[0]
	return intf_ip

def update_metadata(instance_uuid, listening_port):
	creds = {}
#	creds['username'] = "dbryson"
#	creds['api_key'] = "ayem4faK"
#	creds['auth_url'] = "http://172.16.0.2:5000/v2.0"
#	creds['project_id'] = "admin"

	creds['username'] = "admin"
	creds['api_key'] = "admin"
	creds['auth_url'] = "http://172.16.0.2:5000/v2.0"
	creds['project_id'] = "admin"

	nova = nvclient.Client(**creds)
	servers = nova.servers.list()
	instance = ""

	for s in servers:
	    if s.id == instance_uuid:
		instance = s

	log.debug("updating instance '%s' metadata" % s.id)
	serial_debug = { 'serial_debug': listening_port }

	try:
		nova.servers.set_meta(instance, serial_debug)
	except Exception as e:
		log.exception
		

def create_fw_rules(port):
	log.error("creating firewall rules")
	ipm = linux_net.iptables_manager
	ipt = ipm.ipv4['filter']
	ipt.add_rule("INPUT","-p tcp  --dport " + str(port) + " -j ACCEPT")
	ipm.apply()

def del_fw_rules(port):
	ipm = linux_net.iptables_manager
	ipt = ipm.ipv4['filter']
	for rule in ipt.rules:
		log.error(str(rule))
	num_rules = ipt.remove_rule('INPUT','-p tcp  --dport ' + port + ' -j ACCEPT')
	if num_rules:
		log.error("found %s rule regex" % num_rules)
	ipm.apply()
	log.error("removed firewall rules")

def find_serial_port_xml(xml_dom):
	phy_serial = ""
	serial = xml_dom.findall('.//serial')
	for port in serial:
		if port.attrib['type'] == "pty":
			source = port.find('.//source')
			phy_serial = source.attrib['path']
			log.error("Found device %s" % phy_serial)
	return phy_serial

def get_port_num():
	sock = socket.socket()
	sock.bind(('', 0))
	port = sock.getsockname()[1]
	sock.close()
	return port	

def start_socat(lockfile, port, serial):
	log.error("spawning socat")
	socat_call = "/usr/bin/socat -W " + lockfile + " tcp-l:" + str(port) + ",reuseaddr,fork file:" + serial + ",nonblock &"
        utils.execute('chown', 'nova', serial, run_as_root=True)
	log.error("trying to run '%s'" % socat_call)
	os.system(socat_call)

# before killing socat, read the port it is listening to out of the cmdline args
def kill_socat(pid):
	socat_proc = open("/proc/" + pid + "/cmdline","r")
	socat_cmd = socat_proc.readline()
	regex = re.compile(".*tcp-l:([0-9]+),.*")
	port = regex.match(socat_cmd).group(1)

	os.kill(int(pid),signal.SIGTERM)
	log.error("terminated socat pid %s" % pid)
	return port


def check_for_lockfile(instance_name):
	pid = 0
	lockfile = lockfile_path + instance_name + ".lock"
	log.error("looking for lockfile %s" % lockfile)
	if os.path.isfile(lockfile):
		lockfile_fd = open(lockfile, 'r')
		pid = lockfile_fd.readline()
		log.error("Found socat pid %s" % pid)
		lockfile_fd.close()
	return pid


if __name__ == "__main__":
	detach_debug('instance-00000007')
	#attach_debug('instance-00000007', 'cea77836-9690-49b9-b21f-c445891b6e6e')

