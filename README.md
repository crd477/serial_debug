serial-debug
=======

This code implements a remote serial port attached to a openstack instance.

Once installed the module will create a tcp serial port for every instance
created on that hypervisor, and populate the instance metadata with the
information about where the port can be found.  The code assumes that
the hypervisor nodes are reachable and routable from a clients machine.

installation
============
To install, one needs to copy the serial\_debug module to the hypervisor node
and use setup tools to install it into the system:

$ cd serial\_debug
$ python setup.py install

Then apply the patch to nova/compute/manager.py

$ cd /usr/lib/python/site-packages/nova/compute
$ patch -p0 add\_instance\_hook.diff

Then restart the nova-api client, and the hook should be functioning.

*IMPORTANT*
The credentials present in the update\_metadata function inside
serial\_debug.py must be updated for your cluster

Also make sure that socat is installed on your hypervisor nodes.

implementation notes
====================

It uses the openstack 'hooks' framework which is *not* API compatible with
any releases except the one it is written for.

Thanks
======

A big thanks to everyone who helped me implement this in #openstack on
freenode.  As well as Giorgio Franceschi who's pinhead hook helped me
get ideas on how I should be writing my implemenation.

