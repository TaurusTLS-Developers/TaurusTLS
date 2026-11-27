# TaurusTLS documentation

User guidance starts with the [1.1 migration guide](../Migration_to_1_1.md).
Design documentation is grouped by subsystem under `Design/`. Example-specific
documentation belongs alongside examples under `examples/`.

## Design documents

| Subsystem | Architecture | Implementation details |
| --- | --- | --- |
| IOHandlers | [Initialization and AutoLoad](Design/IOHandlers/IOHandler_init_HLD.md) | [Detailed design](Design/IOHandlers/IOHandler_init_DDD.md) |
| Loader | [Library discovery and effective settings](Design/Loader/Loader_paths_HLD.md) | [Detailed design](Design/Loader/Loader_paths_DDD.md) |
| Providers | [OpenSSL lifecycle and configuration](Design/Providers/openssl_providers_HLD.md) | [Detailed design](Design/Providers/openssl_providers_DDD.md) |
| Legacy provider | [Optional Legacy provider](Design/Providers/legacy_providers_HLD.md) | [Detailed design](Design/Providers/legacy_providers_DDD.md) |

[Explicit loading examples](Design/Providers/explicit_loading_migration.md) complement the migration guide.
## Configuration examples

[OpenSSL Legacy and FIPS provider configurations](examples/OpenSSL/README.md), including FIPS installation commands.
