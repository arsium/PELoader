# PELoader

A PE loader written in pure C with Nt routines.

Supports :

* Relocations
* Map sections & Headers
* Imports
* Cloak headers : steals the header of ntdll
* x86 & x64 architecture

Improvements : 

* Indirect syscalls
* Hook detection
* ETW Patching
* ...

Thx to :

* [Manual Loader](https://github.com/adamhlt/Manual-DLL-Loader)
* [PE Packer](https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/)
