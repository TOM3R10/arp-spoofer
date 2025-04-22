DISCLAIMER: THIS PROGRAM IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.  
THE AUTHOR DOES NOT CONDONE OR SUPPORT ANY ILLEGAL OR MALICIOUS USAGE OF THIS TOOL.  
USE THIS SOFTWARE ONLY IN TESTING ENVIRONMENTS OR ON NETWORKS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST.  
THE AUTHOR ASSUMES NO RESPONSIBILITY FOR ANY DAMAGE CAUSED BY THE MISUSE OF THIS PROGRAM.


To use this program add following files with target machine and router information:
1. config.h :
```c
#ifndef CONFIG_H
#define CONFIG_H
// Contains sensitive information the user should replace
#define ROUTER_IP_HEX (uint8_t[4]){0xFF, 0xFF, 0xFF, 0xFF} // Router IP
#define CUSTOM_MAC_HEX (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} // spoofed MAC address
#define CUSTOM_IP_HEX (uint8_t[4]){0xFF, 0xFF, 0xFF, 0xFF} // Target machine IP
#define VICTEM_MAC_HEX (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} // Targer machine MAC
#define ROUTER_MAC_HEX (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} Router MAC

#endif //CONFIG_H
```
  
2. config.py :
```py
TARGET_MACHINE_IP = "192.168.1.223" # Target machine IP in string format
TARGET_MACHINE_MAC = "FF:FF:FF:FF:FF:FF" # Target machine MAC in string format
ROUTER_MAC = "FF:FF:FF:FF:FF:FF" # Router MAC in string format
```

To compile the c program :
```sh
gcc -o main main.c spoofer.c
```

**To use the program run main.py and main.c with correct config files simultaneously.**

Additional featuers to be added:
1. Auto router MAC and IP detection
2. Netowrk scanner for all available machines
3. GUI
4. Abillty to modify packets sent from spoffed machine
