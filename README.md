# Building

## Native Toolchain

```sh
mkdir build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF .. 
cmake --build .
```

## Docker

```sh
docker build -f Dockerfile.server -t michaelkuc6/wgmesh-server .
```

# How to Run

## Server

```sh
docker run --network=host --cap-add=NET_ADMIN -it michaelkuc6/wgmesh-server
```

# Development

## GitHooks

```sh
git config core.hooksPath .githooks
```

## Tests

Can either be run as user, in which case, will fail to fully setup network in `server/public-protocol` test:

```sh
cd build
ctest --output-on-failure
```

Alternatively, the command can be given the `CAP_NET_ADMIN` capability. This allows the test to correctly set up and
tear down the WireGuard interface:

```sh
sudo -E capsh --caps='cap_setpcap,cap_setuid,cap_setgid+ep cap_net_admin+eip' --keep=1 --user="$USER" --addamb="cap_net_admin" --shell=/usr/bin/ctest -- --output-on-failure
```
