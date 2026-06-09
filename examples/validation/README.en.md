# LiteWaf Local Validation Examples

> Language / 语言: [中文](README.md) | [English](README.en.md)

These examples validate a LiteWaf instance that you started locally. They assume Dashboard/API at `http://localhost:18080`, Gateway at `http://localhost:18081`, Host `example.local`, and the validation upstream from `deploy/upstream/default.conf`. Follow the [README quick start](../../README.md#english-guide), create a protected application and policy, then publish default rules before running the examples.

Expected results: normal requests are proxied, SQLi/XSS-style payloads are blocked or observed according to published rules, unknown Host combinations fail closed, and logs can be inspected through API/Dashboard queries. The examples are not production traffic generators and should not be run against third-party systems.
