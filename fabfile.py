from fabric.api import run, env, cd, put, reboot, prefix, shell_env
from contextlib import closing
from fabric.contrib.files import upload_template
from urllib2 import urlopen
import os
import hashlib

# chroot directory for the installation
env.chroot = "/mnt/gentoo"

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

def download_latest_portage():
    url = "http://ftp.jaist.ac.jp/pub/Linux/Gentoo/snapshots/portage-latest.tar.bz2"
    portage_latest_path = "downloads/portage.tar.bz2"

    download_base_file(url, portage_latest_path, hashlib.md5)

    return portage_latest_path

def download_latest_stage3(build_arch="amd64", build_proc="amd64"):
    stage3_latest_url = get_latest_stage3(build_arch, build_proc)
    stage3_path = "downloads/stage3.tar.bz2"

    download_base_file(stage3_latest_url, stage3_path, hashlib.sha512)

    return stage3_path

def download_base_file(url, local_path, hash_algorithm):
    if not os.path.exists(local_path):
        with closing(urlopen(url)) as r:
            with open(local_path, 'wb') as w:
                w.write(r.read())

    if not check_digest(url, local_path, hash_algorithm):
        raise Exception

def check_digest(url, local_path, hash_algorithm):
    if hash_algorithm == hashlib.md5:
        digest = get_digest_from_url(url, '.md5sum')
    elif hash_algorithm == hashlib.sha512:
        digest = get_digest_from_url(url, '.DIGESTS')
    else:
        raise Exception

    print("digest of latest portage is %s" % (digest))
    h = hash_algorithm(open(local_path, 'rb').read())
    print("digest of %s is %s" % (local_path, h.hexdigest()))
    return digest == h.hexdigest()

def get_digest_from_url(base_url, digest_type):
    url = base_url + digest_type
    file_name = base_url.split("/")[-1]
    with closing(urlopen(url)) as r:
        for line in r.readlines():
            if line.startswith('#'):
                continue
            line = line.rstrip()
            digest, name = line.split('  ')
            if name == file_name:
                return digest
   
def make_file_systems():
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
    run("mkfs.ext2 /dev/sda1")
    run("mkfs.ext4 /dev/sda4")


def mount_file_systems():
    run("swapon /dev/sda3")
    run("mount /dev/sda4 %s" % (env.chroot))

    with cd(env.chroot):
        run("mkdir boot")
        run("mount /dev/sda1 boot")

def upload_and_decompress_stage3_and_portage():
    stage3_path = download_latest_stage3()
    portage_path = download_latest_portage()
    with cd(env.chroot):
        stage3_file_name = stage3_path.split('/')[-1]
        put(stage3_path, stage3_file_name)
        portage_file_name = portage_path.split('/')[-1]
        put(portage_path, portage_file_name)

        run('tar xpf "%s"' % (stage3_file_name))
        run('rm "%s"' % (stage3_file_name))

        run('tar xjf %s -C %s' % (portage_file_name, "usr"))
        run('rm "%s"' % (portage_file_name))

def exec_with_chroot(command):
    run('chroot "%s" %s' % (env.chroot, command))

def exec_with_chroot_and_new_env(command):
    exec_command = ' && '.join(['env-update', 'source /etc/profile', command])
    exec_with_chroot('/bin/bash -c "%s"' % (exec_command))

def prepare_chroot():
    run('mount -t proc none "%s/proc"' % (env.chroot))
    run('mount --rbind /dev "%s/dev"' % (env.chroot))

    run('cp /etc/resolv.conf "%s/etc/"' % (env.chroot))
    exec_with_chroot('env-update')

def build_gentoo():
    make_file_systems()
    mount_file_systems()

    upload_and_decompress_stage3_and_portage()
    prepare_chroot()

    with cd(env.chroot):
        run('date -u > "%s/etc/vagrant_box_build_time"' % (env.chroot))

    setting_portage()
    setting_network()
    setting_mounts()
    set_timezone()
    set_locale()

    kernel()
    setting_vagrant()
    install_vmware_tools()
    install_ruby()
    install_chef()
    install_cron()
    install_syslog()
    install_nfs()
    install_grub()
    cleanup()
    zerodisk()
    #reboot()

def setting_network():
    command = 'ln -s /dev/null /etc/udev/rules.d/80-net-name-slot.rules'
    exec_with_chroot(command)
    net_file = 'files/net'
    put(net_file, env.chroot + '/etc/conf.d/net')
    commands = []
    commands.append('ln -s net.lo /etc/init.d/net.eth0')
    commands.append('rc-update add net.eth0 default')
    commands.append('rc-update add sshd default')
    map(exec_with_chroot, commands)

def get_make_conf_env():
    make_conf_env = {}
    # these two (configuring the compiler) and the stage3 url can be changed to build a 32 bit system
    make_conf_env["accept_keywords"] = "amd64"
    make_conf_env["chost"] = "x86_64-pc-linux-gnu"
    # number of cpus in the host system (to speed up make and for kernel config)
    nr_cpus = int(run("cat /proc/cpuinfo | grep processor | wc -l"))
    print("number of cpu is %d" % (nr_cpus))
    make_conf_env["nr_cpus"] = nr_cpus
    make_conf_env["nr_cpus2"] = nr_cpus + 1
    return make_conf_env
 
def setting_mounts():
    fstab_file = 'files/fstab'
    put(fstab_file, env.chroot + '/etc/fstab')

def setting_portage():
    make_conf_file = 'files/make.conf'
    make_conf_env = get_make_conf_env()
    upload_template(make_conf_file, env.chroot + '/etc/portage/make.conf', make_conf_env, backup=False)
    package_keywords = 'files/package.keywords'
    put(package_keywords, env.chroot + '/etc/portage/package.keywords')
    exec_with_chroot_and_new_env('emerge --sync --quiet')

def set_timezone():
    # timezone (as a subdirectory of /usr/share/zoneinfo)
    timezone = "Japan"
    command = 'ln -sf /usr/share/zoneinfo/%s /etc/localtime' % (timezone)
    exec_with_chroot(command)

def set_locale():
    locale = "en_US.utf8"
    run('echo LANG="%s" > %s/etc/env.d/02locale' % (locale, env.chroot))

def kernel():
    package_use_file = 'files/package.use'
    put(package_use_file, env.chroot + '/etc/portage/package.use')

    # kernel version to use
    remote_env = dict()
    remote_env["kernel_version"] = "3.8.13"

    emerge('=sys-kernel/gentoo-sources-%s"' % (remote_env['kernel_version']))

    kernel_config = 'files/.config'
    put(kernel_config, env.chroot + '/usr/src/linux/.config')

    command = 'cd /usr/src/linux && make && make modules_install && make install"'
    exec_with_chroot_and_new_env(command)

def install_grub():
    emerge('grub')
    exec_with_chroot_and_new_env('grep -v rootfs /proc/mounts > /etc/mtab')

    commands = []
    commands.append('sed -i "s/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/g" /etc/default/grub')
    commands.append('mkdir /boot/grub2')
    commands.append('grub2-mkconfig -o /boot/grub2/grub.cfg')
    commands.append('grub2-install --no-floppy /dev/sda')
    
    map(exec_with_chroot, commands)

def test_mount():
    run('mount /dev/sda4 /mnt/gentoo')
    run('mount /dev/sda1 /mnt/gentoo/boot')
    run('mount -t proc none "%s/proc"' % (env.chroot))
    run('mount --rbind /dev "%s/dev"' % (env.chroot))

def emerge(arg):
    exec_with_chroot_and_new_env('emerge %s' % (arg))
    
def install_ruby():
    emerge('--autounmask-write ruby:1.9')
    exec_with_chroot('eselect ruby set ruby19')

def test_chroot():
    with prefix('chroot %s' % (env.chroot)):
        run('pwd')

def install_chef():
    exec_with_chroot('gem install chef --no-rdoc --no-ri')

def install_syslog():
    emerge('app-admin/rsyslog')
    exec_with_chroot('rc-update add rsyslog default')

def install_cron():
    emerge('sys-process/vixie-cron')
    exec_with_chroot('rc-update add vixie-cron default')

def install_nfs():
    emerge('net-fs/nfs-utils')
    with shell_env(FEATURES='-sandbox'):
        emerge('net-fs/autofs')

def install_vmware_tools():
    
    emerge('--autounmask-write app-emulation/vmware-tools')

    with cd(env.chroot):
        vmware_iso = 'opt/vmware/lib/vmware/isoimages/linux.iso'
        mount_path = 'mnt/vmware-tools'
        run('mkdir %s' % (mount_path))
        run('mkdir etc/rc.d')
        with cd('etc/rc.d'):
            run('mkdir rc{0..6}.d')
        run('mount -t iso9660 %s %s' % (vmware_iso, mount_path))
        vm_tool_file = 'VMwareTools-*.tar.gz'
        tmp_dir = 'tmp'
        run('tar xzf %s -C %s' % ('/'.join((mount_path, vm_tool_file)), tmp_dir))
        command = '%s/vmware-tools-distrib/vmware-install.pl -d' % (tmp_dir)
        exec_with_chroot_and_new_env(command)
        run('umount %s' % (mount_path))
        put('files/vmware-tools', 'etc/init.d/vmware-tools')
        run('chmod +x etc/init.d/vmware-tools')

        exec_with_chroot('rc-update add vmware-tools default')

def setting_vagrant():
    remote_env = dict()
    remote_env["password_root"] = "vagrant"
    remote_env["password_vagrant"] = "vagrant"
    # the public key for vagrants ssh
    remote_env["vagrant_ssh_key_url"] = "https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub"

    exec_with_chroot('mkdir -p /home/vagrant/.ssh')
    exec_with_chroot('chmod 700 /home/vagrant/.ssh')
    exec_with_chroot('wget --no-check-certificate "%s" -O "/home/vagrant/.ssh/authorized_keys"' % (remote_env["vagrant_ssh_key_url"]))
    exec_with_chroot('chmod 600 /home/vagrant/.ssh/authorized_keys')

    #cp -f /root/.vbox_version "$chroot/home/vagrant/.vbox_version"

    # for passwordless logins
    exec_with_chroot('mkdir -p /root/.ssh')
    #cat /tmp/ssh-root.pub >> "$chroot/root/.ssh/authorized_keys"

    # add vagrant user
    exec_with_chroot('groupadd -r vagrant')
    exec_with_chroot('useradd -m -r vagrant -g vagrant -G wheel -c "added by vagrant"')

    # set passwords (for after reboot)
    run('echo %s > %s' % (remote_env["password_root"], env.chroot + '/tmp/root-password'))
    run('echo %s >> %s' % (remote_env["password_root"], env.chroot + '/tmp/root-password'))

    run('echo %s > %s' % (remote_env["password_vagrant"], env.chroot + '/tmp/vagrant-password'))
    run('echo %s >> %s' % (remote_env["password_vagrant"], env.chroot + '/tmp/vagrant-password'))

    exec_with_chroot('/bin/bash -c "passwd < %s"' % ('/tmp/root-password'))
    exec_with_chroot('/bin/bash -c "passwd vagrant < %s"' % ('/tmp/vagrant-password'))

    exec_with_chroot('chown -R vagrant /home/vagrant')

    emerge('app-admin/sudo')

    run('echo "sshd:ALL" > %s' % (env.chroot + '/etc/hosts.allow'))
    run('echo "ALL:ALL" > %s' % (env.chroot + '/etc/hosts.deny'))
    run('echo "vagrant ALL=(ALL) NOPASSWD: ALL" >> %s' % (env.chroot + '/etc/sudoers'))

    with cd(env.chroot + '/etc/ssh'):
        put('files/sshd_config', 'sshd_config')


def cleanup():
    exec_with_chroot('eselect news read all')

    run('rm -rf %s/tmp/*' % (env.chroot))
    run('rm -rf %s/var/log/*' % (env.chroot))
    exec_with_chroot('rm -rf /root/.gem')

def zerodisk():
    empty_file_path = env.chroot + '/boot/EMPTY'
    run('dd if=/dev/zero of=%s bs=1M || true' % (empty_file_path))
    run('rm %s' % (empty_file_path))
    
    empty_file_path = env.chroot + '/EMPTY'
    run('dd if=/dev/zero of=%s bs=1M || true' % (empty_file_path))
    run('rm %s' % (empty_file_path))
    #reboot()
    run('reboot')
