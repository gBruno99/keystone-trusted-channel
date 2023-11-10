# keystone-trusted-channel
Thesis implementation "	Design and Implementation of Trusted Channels in the Keystone Framework"

## Build
The only requirement is a built version of keystone that you can find at this link: [keystone](https://github.com/keystone-enclave/keystone)

Otherwise you can see my fork of that repository at this [link](https://github.com/gBruno99/keystone/tree/dev_test_DICE)
If you don't have it, follow the guide that you can find in the previous links.

After having cloned the repository, the file `/keystone/skd/macros.cmake` must be updated, adding in macro **get_runtime_dir** the path to keystone's runtime from the the directory of this project.

Then you have to run `$ ./quick-start.sh` (`/keystone-trusted-channel` as working directory), that will download the [MBedTLS](https://github.com/Mbed-TLS/mbedtls) repository and build the whole project. At the end it will copy the generated executables in `/keystone/<build_dir>/overlay/root/` directory.

## Running the executable
After having launched from CLI the script **quick-start.sh**, you have to spawn three terminals.
### Terminal 1 - XCA
Launch server-CA:

`$ ./build/server-CA/server-CA`

### Terminal 1 - Ver
Launch server-verifier:

`$ ./build/server-verifier/server-verifier`

### Terminal 3 - TA
Launch enclave-Alice.ke from the directory `/keystone/<build_dir>`:

`$ make image`

`$ ./scripts/run-qemu.sh`

Then from QEMU interface, you sign in as login: **root** and password: **sifive** and run the following commands:
- `# insmod keystone-driver.ko` - insert the linux driver for keystone
- `# ./enclave-Alice.ke` - launch the enclave application           

## Get attestation
In order to update the reference values for verification, after a first execution of **quick-start.sh**, and keystone's **make image** you need to run from `/keystone-trusted-channel/scripts` the following command `$ ./update_reference_values.sh`

Replace **<path_to_keystone_dir>** with the path of your keystone,  **<build_dir>** with the name of your keystone build directory

Then re-build the project as explained in build section

## Issues
You may encounter two issues:
- the first is related to **macros.cmake**, if your cmake fails in building the project it is possible that you have to build your keystone's sdk directory. Follow the instruction available at this [link](https://github.com/keystone-enclave/keystone-sdk/blob/master/sdk/README.md)
- the second is in the **get-attestation.sh** script. In order to be executed, in the system there mustn't be any running instances of qemu.




