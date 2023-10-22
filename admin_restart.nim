when defined(windows):
    import std/tempfiles
    import std/os
    import std/strutils
    import winlean

    proc winRunAsAdmin*() =
        if not isAdmin():
            try:
                let (cfile, path) = createTempFile("writetest_", ".tmp", ".")
                close(cfile)
                discard tryRemoveFile(path)
            except OSError:
                discard winlean.shellExecuteW(0, newWideCString("runas"), newWideCString(os.getAppFilename()), newWideCString(commandLineParams().join(" ")), newWideCString(""), SW_SHOWNORMAL)
                quit(-1)
else:
    proc winRunAsAdmin*() =
        discard
    
    