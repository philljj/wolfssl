# wolfSSL bsdkm (bsd kernel module)

libwolfssl supports building as a FreeBSD kernel module (`libwolfssl.ko`).
When loaded, wolfCrypt and API are made available to the rest of
the kernel, supporting cryptography in kernel space.

## Building and Installing

Build bsdkm with:

```sh
./configure --enable-freebsdkm --enable-cryptonly && make
```

note: replace `/usr/src/linux` with a path to your fully configured and built
target kernel source tree.

Assuming you are targeting your native system, install with:

```sh
sudo kldload bsdkm/libwolfssl.ko
```

You should see it now:
```sh
kldstat -m libwolfssl
Id  Refs Name
509    1 libwolfssl
```

### options

| freebsdkm option                 | description                              |
| :------------------------------- | :--------------------------------------- |
| --with-bsd-export-syms=LIST      | Export list of symbols as global. <br>. Options are 'all', 'none', or <br> comma separated list of symbols. |
| --with-kernel-source=PATH        | Path to kernel tree root (default `/usr/src/sys`) |

