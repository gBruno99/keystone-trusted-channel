# keystone-trusted-channel
Thesis implementation "Trusted channel with endpoint attestation"

## Build
The only requirement is a built version of keystone that you can find at this link: [keystone](https://github.com/keystone-enclave/keystone)

Otherwise you can see my fork of that repository at this [link](https://github.com/gBruno99/keystone)
If you don't have it, follow the guide that you can find in the previous links.

After having cloned the repository, the file `/keystone/skd/macros.cmake` must be updated, adding in macro **get_runtime_dir** the path to keystone's runtime from the the directory of this project.

Then you have to run `$ ./quick-start.sh` (`/keystone-trusted-channel` as working directory), that will download the [MBedTLS](https://github.com/Mbed-TLS/mbedtls) repository and build the whole project. At the end it will copy the generated executables in `/keystone/<build_dir>/overlay/root/` directory.

## Running the executable
After having launched from CLI the script **quick-start.sh**, you have to run the following commands from the directory `/keystone/<build_dir>`

`$ make image`

`$ ./scripts/run-qemu.sh`

Then from QEMU interface, you sign in as login: **root** and password: **sifive** and run the following commands:
- `# insmod keystone-driver.ko` - insert the linux driver for keystone
- `# ./server-CA.riscv &` - launch in background the CA server
- `# ./enclave-Alice.ke` - launch the enclave application           

## Get attestation
in order to get the reference values for verification, after a first execution of **quick-start.sh**, you need to run from `/keystone-trusted-channel/scripts` the following command `$ KEYSTONE_BUILD_DIR=<path_to_keystone_dir>/keystone/<build_dir> ./get_attestation.sh ../my_mbedtls_stdlib/include/`

Replace **<path_to_keystone_dir>** with the path of your keystone,  **<build_dir>** with the name of your keystone build directory

Then re-build the project as explained in build section

## Issues
You may encounter two issues:
- the first is related to **macros.cmake**, if your cmake fails in building the project it is possible that you have to build your keystone's sdk directory. Follow the instruction available at this [link](https://github.com/keystone-enclave/keystone-sdk/blob/master/sdk/README.md)
- the second is in the **get-attestation.sh** script. In order to be executed, in the system there mustn't be any running instances of qemu.




