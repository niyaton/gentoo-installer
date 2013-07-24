from fabric.api import run
from urllib2 import urlopen

def hello():
    print("Hello World!")

def get_latest_stage3(build_arch, build_proc):
    # stage 3 filename and full url
    # retrieve from Gentoo current autobuild txt - these change regularly
    stage3_current_url = \
        "http://distfiles.gentoo.org/releases/%s/autobuilds/latest-stage3-%s.txt" \
            % (build_arch, build_proc)
    print("Get latest stage3 location from:%s" % (stage3_current_url))
    r = urlopen(stage3_current_url)

    stage3_latest_base = "http://distfiles.gentoo.org/releases/%s/autobuilds/%s"
    for line in r.readlines():
        if not line.startswith("#"):
            stage3_current_url = stage3_latest_base % (build_arch, line.strip())
            break

    print("Latest stage3 file is here: %s" % (stage3_current_url))
    return stage3_current_url

def setting(build_arch="amd64", build_proc="amd64"):
    get_latest_stage3(build_arch, build_proc)
#run("stage3current=\`curl -s http://distfiles.gentoo.org/releases/\${build_arch}/autobuilds/latest-stage3-\${build_proc}.txt|grep -v "^#"\`
#export stage3url="http://distfiles.gentoo.org/releases/\${build_arch}/autobuilds/\${stage3current}"
#export stage3file=\${stage3current##*/}
#
## these two (configuring the compiler) and the stage3 url can be changed to build a 32 bit system
#export accept_keywords="amd64"
#export chost="x86_64-pc-linux-gnu"
#
## kernel version to use
#export kernel_version="3.7.10"
#
## timezone (as a subdirectory of /usr/share/zoneinfo)
#export timezone="UTC"
#
## locale
#export locale="en_US.utf8"
#
## chroot directory for the installation
#export chroot=/mnt/gentoo
#
## number of cpus in the host system (to speed up make and for kernel config)
#export nr_cpus=$(</proc/cpuinfo grep processor|wc -l)
#
## user passwords for password based ssh logins
#export password_root=vagrant
#export password_vagrant=vagrant
#
## the public key for vagrants ssh
#export vagrant_ssh_ke
