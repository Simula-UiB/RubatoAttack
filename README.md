<p align="center">
    <a href="https://github.com/Simula-UiB/CryptaPath/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

## Licence
Rubato Attack is licensed under the MIT License.

* MIT license ([LICENSE](../LICENSE) or http://opensource.org/licenses/MIT)

# Rubato Attack
This repository contains code written in C for testing an attack on the Rubato cipher with weak values of the modulus q.  The code depends on the DGS library (https://github.com/malb/dgs), which needs to be installed first to compile the program.  Assuming the DGS library is installed, the program testing the attack is built simply by compiling testAttack.c, making sure rubato.h and attack.h exist in the same folder.

Running the code as is will successfully identify the correct key values modulo 5 on Rubato-128M, guessing on six elements of the unknown key.  Comments in testAttack.c indicate what to modify to test the attack on other Rubato variants, and how to guess on a different number of key elements.
