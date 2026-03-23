# vBSD Coalition

Capability-based resource group management for FreeBSD. Group processes, jails, and other capabilities that should be revoked together.

## Quick Start

```sh
make                    # Build module and tests
sudo kldload ./sys/modules/vbsd_coalition/vbsd_coalition.ko
sudo ./tests/bin/coalition_test
```

## The Pattern

```c
// Supervisor creates coalition
coalition_fd = open("/dev/vbsd_coalition", O_RDWR);

// Enlist resources (processes, jails, sockets, devices, etc.)
ioctl(coalition_fd, VBSD_COALITION_ENLIST, &resource_fd);

// Close coalition → all resources terminated
close(coalition_fd);
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for full documentation.

## License

BSD-2-Clause
