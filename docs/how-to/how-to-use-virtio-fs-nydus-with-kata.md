# Kata Containers with virtio-fs-nydus

## Introduction

Research shows that time to take for pull operation accounts for 76% of container startup time but only 6.4% of that data is read. so if we can get data on demand (lazyload), it will speed up the container start. [Nydusd](https://github.com/dragonflyoss/image-service) is the project which build image with new format and can get data on demand when container start.

> **Notes:** The feature is not completely finished, if you want to try, you can do as follows,

1. Use [nydus latest branch](https://github.com/dragonflyoss/image-service)

2. Depoly nydus environment as [Nydus Setup for Containerd Environment](https://github.com/dragonflyoss/image-service/blob/master/docs/containerd-env-setup.md);

3. Use kata-containers `support_nydus` branch to compile and build kata-containers.img;

4. Update shared_fs to `virtio-fs-nydus`, `internetworking_model="none"` and `disable_new_netns = true`

5. run `crictl run -r kata-qemu container-config.yaml pod-config.yaml`
