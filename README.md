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
- victim can provide any secret byte to access through first command line argument, i.e., taskset -c 4 ./victim 'A'
- Both attacker and victim should run simultaniously
