sudo qemu-system-mipsel \
-M malta \
-kernel vmlinux-3.2.0-4-4kc-malta \
-hda debian_wheezy_mipsel_standard.qcow2 \
-append "root=/dev/sda1 console=tty0" \
-net nic \
-net tap \
-nographic \
