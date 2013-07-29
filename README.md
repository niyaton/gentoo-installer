gentoo-installer
================

Yet Another Gentoo Installer by Fabric.

# Requirements
- fabric

# Developement Environment
- Python 2.7
- Fabric 1.6.1
- Mac OSX 10.8

# Usage
## Setup of Installation Environment 
    # First you need to set up network for SSH connection in the target machine.
    $ <some command to set up netwrok>
    # Then, you need to set a temporal password to access target machine via SSH.
    $ passwd
    # Finally, you need to start up SSH Deamon.
    $ /etc/init.d/sshd start
    
## Setup Gentoo Server from local machine by Fabric
    fab -H <host name or IP address> -u root -p <temporal password of root> build_gentoo