# Attack Code
### Compilation
make
### Run
taskset -c 0 ./attack

# Victim Code
### Compilation
make
### Run
taskset -c 4 ./victim

# Note
- Both attacker and victim should be running on sibling hyperthreaded cores
- Victim can provide any secret byte to access through first command line argument, i.e., taskset -c 4 ./victim 'A'
- Both attacker and victim should run simultaniously
- Grub command line arguments: GRUB_CMDLINE_LINUX_DEFAULT="hugepagesz=4096 quiet splash nox2apic iomem=relaxed no_timer_check nosmep nosmap isolcpus=1 dis_ucode_ldr tsx=off"
