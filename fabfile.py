from fabric.api import run, shell_env, env, cd, put, open_shell
from fabric.contrib.files import upload_template
from urllib2 import urlopen
import os
import hashlib

env.chroot = "/mnt/gentoo"

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

def download_latest_portage(url="http://ftp.jaist.ac.jp/pub/Linux/Gentoo/snapshots/portage-latest.tar.bz2"):
    portage_latest_path = "downloads/portage.tar.bz2"
    if not os.path.exists(portage_latest_path):
        r = urlopen(url)
        with open(portage_latest_path, 'wb') as w:
            w.write(r.read())

    if not check_portage_md5sum(url, portage_latest_path):
        raise Exception
    return portage_latest_path

def check_portage_md5sum(url, portage_latest_path):
    digest = get_portage_md5sum(url)
    print("digest of latest portage is %s" % (digest))
    h = hashlib.md5(open(portage_latest_path, 'rb').read())
    print("digest of %s is %s" % (portage_latest_path, h.hexdigest()))
    return digest == h.hexdigest()

def download_latest_stage3(build_arch="amd64", build_proc="amd64"):
    stage3_latest_url = get_latest_stage3(build_arch, build_proc)
    stage3_path = "downloads/stage3.tar.bz2"
    if not os.path.exists(stage3_path):
        r = urlopen(stage3_latest_url)
        with open(stage3_path, 'wb') as w:
            w.write(r.read())

    if not check_stage3_md5sum(stage3_latest_url, stage3_path):
        raise Exception
    return stage3_path

def check_stage3_md5sum(stage3_latest_url, stage3_path):
    digest = get_stage3_digest(stage3_latest_url)
    print("digest of latest stage3 is %s" % (digest))
    h = hashlib.sha512(open(stage3_path, 'rb').read())
    print("digest of %s is %s" % (stage3_path, h.hexdigest()))
    return digest == h.hexdigest()


def get_digest_from_url(base_url, digest_type):
    url = base_url + digest_type
    file_name = base_url.split("/")[-1]
    r = urlopen(url)
    for line in r.readlines():
        if line.startswith('#'):
            continue
        line = line.rstrip()
        digest, name = line.split('  ')
        if name == file_name:
            return digest

def get_portage_md5sum(stage3_latest_url):
    return get_digest_from_url(stage3_latest_url, '.md5sum')
        
def get_stage3_digest(stage3_latest_url):
    return get_digest_from_url(stage3_latest_url, '.DIGESTS')
    
def setting(build_arch="amd64", build_proc="amd64"):
    stage3_latest_url = get_latest_stage3(build_arch, build_proc)
    stage3_file_name = stage3_latest_url.split("/")[-1]
    print("stage3 file name is %s" % (stage3_file_name))

    remote_env = dict()
    # these two (configuring the compiler) and the stage3 url can be changed to build a 32 bit system
    remote_env["accept_keywords"] = "amd64"
    remote_env["chost"] = "x86_64-pc-linux-gnu"
    # kernel version to use
    remote_env["kernel_version"] = "amd64"
    # timezone (as a subdirectory of /usr/share/zoneinfo)
    remote_env["timezone"] = "UTC"
    # locale
    remote_env["locale"] = "en_US.utf8"
    # chroot directory for the installation
    remote_env["chroot"] = "/mnt/gentoo"
    # number of cpus in the host system (to speed up make and for kernel config)
    nr_cpus = run("cat /proc/cpuinfo | grep processor | wc -l")
    print("number of cpu is %s" % (nr_cpus))
    remote_env["nr_cpus"] = nr_cpus
    # user passwords for password based ssh logins
    remote_env["password_root"] = "vagrant"
    remote_env["password_vagrant"] = "vagrant"
    # the public key for vagrants ssh
    remote_env["vagrant_ssh_key_url"] = "https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub"

def base():
    sgdisk_opts_format = '-n %(id)d:0:%(amount)s -t %(id)d:%(fid)s -c %(id)d:"%(name)s"'
    sgdisk_options = []
    sgdisk_options.append({'id' : 1, "amount" : "+128M", "fid" : "8300", "name" : "linux-boot"})
    sgdisk_options.append({'id' : 2, "amount" : "+32M", "fid" : "ef02", "name" : "bios-boot"})
    sgdisk_options.append({'id' : 3, "amount" : "+4G", "fid" : "8200", "name" : "swap"})
    sgdisk_options.append({'id' : 4, "amount" : "0", "fid" : "8300", "name" : "linux-root"})

    sgdisk_option = ' '.join([ sgdisk_opts_format % i for i in sgdisk_options])
    sgdisk_option += ' -p /dev/sda'
    run("sgdisk %s" % (sgdisk_option))
    run("mkswap /dev/sda3")
    run("swapon /dev/sda3")
    
    run("mkfs.ext2 /dev/sda1")
    run("mkfs.ext4 /dev/sda4")

    run("mount /dev/sda4 %s" % (env.chroot))

    
    stage3_path = download_latest_stage3()
    portage_path = download_latest_portage()
    put(stage3_path, env.chroot)
    put(portage_path, env.chroot)
    with cd(env.chroot):
        run("mkdir boot")
        run("mount /dev/sda1 boot")

        #stage3_latest_url = get_latest_stage3("amd64", "amd64")
        #stage3_file_name = stage3_latest_url.split("/")[-1]

        #run('wget -nv --tries=5 "%s"' % (stage3_latest_url))
        #run('tar xpf "%s"' % (stage3_file_name))
        #run('rm "%s"' % (stage3_file_name))
        
        stage3_file_name = stage3_path.split('/')[-1]
        run('tar xpf "%s"' % (stage3_file_name))
        run('rm "%s"' % (stage3_file_name))

        portage_file_name = portage_path.split('/')[-1]
        run('tar xjf %s -C %s' % (portage_file_name, "usr"))
        run('rm "%s"' % (portage_file_name))

        run('mount -t proc none "%s/proc"' % (env.chroot))
        run('mount --rbind /dev "%s/dev"' % (env.chroot))

        run('cp /etc/resolv.conf "%s/etc/"' % (env.chroot))
        run('date -u > "%s/etc/vagrant_box_build_time"' % (env.chroot))
        run('chroot "%s" env-update' % (env.chroot))

        command = 'ln -s /dev/null /etc/udev/rules.d/80-net-name-slot.rules'
        run('chroot "%s" %s' % (env.chroot, command))
        
        chroot1()
        chroot2()
        chroot3()

def chroot1():
    net_file = 'files/net'
    put(net_file, env.chroot + '/etc/conf.d/net')
    commands = []
    commands.append('ln -s net.lo /etc/init.d/net.eth0')
    commands.append('rc-update add net.eth0 default')
    commands.append('rc-update add sshd default')
    for command in commands:
        run('chroot "%s" %s' % (env.chroot, command))

def get_make_conf_env():
    make_conf_env = {}
    make_conf_env["accept_keywords"] = "amd64"
    make_conf_env["chost"] = "x86_64-pc-linux-gnu"
    # number of cpus in the host system (to speed up make and for kernel config)
    nr_cpus = int(run("cat /proc/cpuinfo | grep processor | wc -l"))
    print("number of cpu is %d" % (nr_cpus))
    make_conf_env["nr_cpus"] = nr_cpus
    make_conf_env["nr_cpus2"] = nr_cpus + 1
    return make_conf_env
 
def chroot2():
    fstab_file = 'files/fstab'
    put(fstab_file, env.chroot + '/etc/fstab')

    make_conf_file = 'files/make.conf'
    make_conf_env = get_make_conf_env()
    upload_template(make_conf_file, env.chroot + '/etc/portage/make.conf', make_conf_env, backup=False)

def chroot3():
    # timezone (as a subdirectory of /usr/share/zoneinfo)
    remote_env = dict()
    remote_env["timezone"] = "Japan"
    commands = [] 
    commands.append('ln -sf /usr/share/zoneinfo/%s /etc/localtime' % (remote_env["timezone"]))

    # locale
    remote_env["locale"] = "en_US.utf8"
    run('echo LANG="%s" > %s/etc/env.d/02locale' % (remote_env["locale"], env.chroot))
    #commands.append('env-update')
    #commands.append('/bin/bash -c "env-update && source /etc/profile && emerge-webrsync"')
    commands.append('/bin/bash -c "env-update && source /etc/profile && emerge --sync --quiet"')
    #commands.append('emerge-webrsync')

    for command in commands:
        run('chroot "%s" %s' % (env.chroot, command))

def kernel():
    package_use_file = 'files/package.use'
    put(package_use_file, env.chroot + '/etc/portage/package.use')

    # kernel version to use
    remote_env = dict()
    remote_env["kernel_version"] = "3.8.13"

    command = '/bin/bash -c "env-update && source /etc/profile && emerge =sys-kernel/gentoo-sources-%s"' % (remote_env['kernel_version'])
    run('chroot "%s" %s' % (env.chroot, command))

    kernel_config = 'files/.config'
    put(kernel_config, env.chroot + '/usr/src/linux/.config')

    command = '/bin/bash -c "env-update && source /etc/profile && cd /usr/src/linux && make && make modules_install && make install"'
    run('chroot "%s" %s' % (env.chroot, command))

def grub():
    package_keywords = 'files/package.keywords'
    put(package_keywords, env.chroot + '/etc/portage/package.keywords')

    commands = []
    commands.append('/bin/bash -c "env-update && source /etc/profile && emerge grub"')
    commands.append('sed -i "s/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/g" /etc/default/grub')
    commands.append('/bin/bash -c "env-update && source /etc/profile && grep -v rootfs /proc/mounts > /etc/mtab"')
    commands.append('mkdir /boot/grub2')
    commands.append('grub2-mkconfig -o /boot/grub2/grub.cfg')
    commands.append('grub2-install --no-floppy /dev/sda')
    
    for command in commands:
        run('chroot "%s" %s' % (env.chroot, command))

def test_mount():
    run('mount /dev/sda4 /mnt/gentoo')
    run('mount /dev/sda1 /mnt/gentoo/boot')
    run('mount -t proc none "%s/proc"' % (env.chroot))
    run('mount --rbind /dev "%s/dev"' % (env.chroot))
