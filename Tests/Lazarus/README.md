# Lazarus collection menu regression

Build with Lazarus and the repository's TaurusTLSRT package available:

```text
lazbuild TaurusTLS.PlatformSettings.Menu.lpi
```

Run `lib/x86_64-win64/PlatformSettingsMenu.exe` on Windows64 (adjust the target
directory for other platforms). A successful run prints PASS and returns zero.
No OpenSSL installation or library loading is needed.

The program queries the collection through the actual LCL `IObjInspInterface`
used by the Object Inspector. It checks Add availability before and after reaching
capacity, deletion and replacement, the unchanged direct-overflow exception, and
the runtime edit guard. This also verifies compatibility of the nonvisual
loader's interface declaration with LCL's GUID and CORBA method layout.

After rebuilding the installed Lazarus IDE, also check the Object Inspector tree
context menu on the collection and its items: Add Item must disappear at six
entries and return after deleting one. Check the collection dialog's Add button
and close/reopen behavior separately.
