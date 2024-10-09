# Basic Demo

* Create file: `dd if=/dev/urandom bs=1K count=300 of=blob.bin`
* Show entropy: `ent blob.bin`
* Show usage: `python3 ../../codasm.py --help`
* Run: `python3 ../../codasm.py -i blob.bin -v -vbch 0.9`