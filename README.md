# Keerpc

A Python implementation of KeepassRPC protocol.

# Installation

```bash
python -m pip install keerpc
```

# Usage

```bash
keerpc path/to/database
```

```bash
keerpc  path/to/database1 path/to/database2 -p 12546 -a 127.0.0.1
```

# Features

Keerpc only support username and password fields. Advanced features of KeepassRPC plugin are not supported.

# Testing and debugging

Enable debug logging:
```bash
keerpc /path/to/database -l "DEBUG"
```

Run tests: 
```bash
python -m unittest tests.test -v
```
