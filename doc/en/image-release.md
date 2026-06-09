# LiteWaf Image Publishing Guide

> Language / 语言: [中文](../镜像发布说明.md) | [English](image-release.md)

This release guide defines the prebuilt image coordinates consumed by the production installer. Before formal CI is available, publish the API, Dashboard, and Gateway images from a trusted build machine, not from the production host.

Production pulls images from `.env`:

```text
LITEWAF_IMAGE_PREFIX=litewaf
LITEWAF_IMAGE_TAG=v1.0.0
```

The resulting image names are:

```text
${LITEWAF_IMAGE_PREFIX}/litewaf-api:${LITEWAF_IMAGE_TAG}
${LITEWAF_IMAGE_PREFIX}/litewaf-dashboard:${LITEWAF_IMAGE_TAG}
${LITEWAF_IMAGE_PREFIX}/litewaf-gateway:${LITEWAF_IMAGE_TAG}
```

Health expectations before publishing or upgrading: API `/healthz` must respond, Dashboard static assets must be served, Gateway `/healthz` must respond, and the production `.env` must not keep weak placeholder secrets such as `change-me`.
