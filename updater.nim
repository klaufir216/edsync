# nimble install https://github.com/niv/ed25519.nim
# nimble install https://github.com/khchen/hashlib
# nimble install argparse
# nimble install glob

# TODO
# - Create error log in case of unknown exception

import ed25519
import base64
import json
import os
import strutils
import hashlib/rhash/sha3
import uri
import options
import argparse
import glob
import ncurl
import retry
import std/strformat
import humanbytes
import keys
import std/times
import pubkeys

const version = "v1.6"
const appname = "updater"

const catalogFilename = appname & "-catalog.sha3"
const signatureFilename = appname & "-catalog.sig"
const edsyncSourceFilename = appname & "-source.json"
const edsyncSignerKeypairFilename = ".edsync-signer-keypair"
const edsyncIgnoreFilename = ".edsyncignore"
const pendingPathPostfix = ".edsync-pending"
const filesWritableCheckTimeout = 60

proc getIgnoreRules(): seq[string] =
    if fileExists(edsyncIgnoreFilename):
        result = readFile(edsyncIgnoreFilename).strip().split('\n')
        return result
    return @[]

proc getExecutableFilename(): string =
    var (_, filename) = os.splitPath(os.getAppFilename())
    return filename

proc getKeypairPath(): string =
    return joinPath(getHomeDir(), edsyncSignerKeypairFilename)

proc genKeypair(): Keypair =
    ed25519.createKeypair(ed25519.seed())

proc copyToArray(s: string, bytes: openarray[byte]) =
  copyMem(bytes[0].unsafeAddr, s[0].unsafeAddr, bytes.len)

proc saveSignature(sig: Signature) =
    var keyFile: File = open(signatureFilename, fmWrite)
    defer: close(keyFile)
    keyFile.write(base64.encode(sig))

proc loadSignatureString(s: string): Signature =
    var sig: Signature
    var sigStr = base64.decode(s)
    assert len(sigStr) == 64, "signature length must be 64 bytes"
    copyToArray(sigStr, sig)
    return sig

proc loadSourceJsonPublicKey(): PublicKey =
    var pk: PublicKey
    var jobj = parseJson(readFile(edsyncSourceFilename))
    var pubkeyStr = jobj["public_key"].getStr()
    if not (pubkeyStr in hardcodedPubkeys):
        echo "error: public key mismatch"
        sleep(5000)
        quit(-1)
    var pkStr = base64.decode(pubkeyStr)
    assert len(pkStr) == 32, "public key must be 32 bytes"
    copyToArray(pkStr, pk)
    return pk

proc loadSourceJsonUrl(): string =
    var jobj = parseJson(readFile(edsyncSourceFilename))
    return jobj["url"].getStr()

proc saveEdsyncKeypair(kp: KeyPair, filename: string) =
    var keyFile: File = open(filename, fmWrite)
    defer: close(keyFile)
    var jobj = newJObject()
    jobj.add("public_key", newJString(base64.encode(kp.publicKey)))
    jobj.add("private_key", newJString(base64.encode(kp.privateKey)))
    keyFile.write($jobj)

proc saveSourceJson(pk: PublicKey, url: string) =
    var edsyncSource: File = open(edsyncSourceFilename, fmWrite)
    defer: close(edsyncSource)
    var jobj = newJObject()
    jobj.add("public_key", newJString(base64.encode(pk)))
    jobj.add("url", newJString(url))
    edsyncSource.write($jobj)

proc loadEdsyncKeypair(filename: string): KeyPair =
    var kp: KeyPair
    var jobj = parseJson(readFile(filename))
    var publicKeyStr = base64.decode(jobj["public_key"].getStr())
    var privateKeyStr = base64.decode(jobj["private_key"].getStr())
    assert len(publicKeyStr) == 32, "error in keypair: public key should be 32 bytes"
    assert len(privateKeyStr) == 64, "error in keypair: private key should be 64 bytes"
    copyToArray(publicKeyStr, kp.publicKey)
    copyToArray(privateKeyStr, kp.privateKey)
    return kp

proc calculateFileSha3(filename: string): string  =
  if not fileExists(filename):
    return ""
  const BufferLength = 8192
  let f = open(filename)
  var state = init[RHASH_SHA3_256]()
  var buffer = newString(BufferLength)
  while true:
    let length = readChars(f, buffer, 0, BufferLength)
    if length == 0:
      break
    buffer.setLen(length)
    state.update(buffer)
    if length != BufferLength:
      break
  close(f)
  return $state.final()

proc calculateStringSha3(s: string): string =
    var state = init[RHASH_SHA3_256]()
    state.update(s)
    return $state.final()

proc checkKeepFile(ignoreRules: seq[string], filename: string): bool =
    result = true
    for rule in ignoreRules:
        var r = rule.strip()
        if r.startsWith("!") and filename.matches(r[1 .. ^1]):
            return true
        if filename.matches(r):
            result = false

proc createCatalog(ignoreRules: seq[string]): int =
    result = 0
    var catalogFile: File = open(catalogFilename, fmWrite)
    defer: close(catalogFile)
    for filenameConst in os.walkDirRec("./"):
        var filename: string = filenameConst
        removePrefix(filename, "./")
        removePrefix(filename, r".\")
        if filename == catalogFilename or
           filename == edsyncSourceFilename or
           filename == edsyncIgnoreFilename or
           filename == signatureFilename or
           filename == getExecutableFilename():
            continue
        if not checkKeepFile(ignoreRules, filename):
            echo("Ignored : " & filename.replace("\\", "/"))
            continue
        filename = filename.replace("\\", "/")
        var fileHash = calculateFileSha3(filename)
        catalogFile.write(fileHash & " *" & filename & "\n")
        echo("Added   : " & filename)
        result += 1

proc signCatalog(kp: KeyPair) =
    var catalogHash = calculateFileSha3(catalogFilename)
    var sig = ed25519.sign(catalogHash, kp)
    saveSignature(sig)

proc verifyStringSignature(s: string, sig: Signature): bool =
    var catalogHash = calculateStringSha3(s)
    var pubkey = loadSourceJsonPublicKey()
    return ed25519.verify(catalogHash, sig, pubkey)

iterator iterateCatalog(catalogContent: string): tuple[hash: string, path: string, index: int, total: int] =
    var isVerbose: bool = false
    var lines = catalogContent.split("\n")
    var items = newSeq[tuple[hash: string, path: string]]()
    for line in lines:
        var temp: seq[string] = line.split(" *", maxsplit=1)
        if len(temp) != 2:
            continue
        var catalogHash = temp[0]
        var path = temp[1]
        if os.isAbsolute(path):
            if isVerbose:
                stderr.writeLine("Catalog: Skipping absolute path: " & path)
            continue
        if ".." in path:
            if isVerbose:
                stderr.writeLine("Catalog: Skipping path with '..': " & path)
            continue
        items.add((catalogHash, path))
        #yield (catalogHash, path)
    var index = 0
    var total = len(items)
    for (catalogHash, path) in items:
        yield (catalogHash, path, index, total)
        index += 1

proc getRemoteUrl(path: string): string =
    return $(parseUri(loadSourceJsonUrl()) / path)

proc getPendingPath(path: string): string =
    path & pendingPathPostfix

proc downloadRemoteFile(remoteHash: string, path: string, currentFile: int, totalFiles: int, isVerbose: bool): Option[string] =
    #proc progressCallback(bytesRead: int, bytesTotal: int) =
    #    stdout.write("\r" & $path & ": " & $bytesRead & " / " & $bytesTotal)

    var localHash = calculateFileSha3(path)
    if remoteHash == localHash:
        return none(string)

    var (dirname, _) = os.splitPath(path)
    os.createDir(dirname)
    var pendingPath = getPendingPath(path)

    # if pendingPath already exists; check hash; only download if needed
    if fileExists(pendingPath) and calculateFileSha3(pendingPath) == remoteHash:
        if isVerbose:
            echo("Already downloaded: " & path)
    else:
        proc onProgress(currentBytes:int, totalBytes: int) =
            if totalBytes > 0:
                # [3 of 61] *filename* 17.23 MB / 149.42 MB
                var msg = fmt"[{currentFile+1} of {totalFiles}] {path} {humanBytes(currentBytes)} / {humanBytes(totalBytes)}"
                stderr.write(fmt"{msg:<79}" & "\r")
        retryVoid[CurlError](proc() = ncurlDownload(getRemoteUrl(path), pendingPath, onProgress),
            max_tries=10, sleep_time_sec=5)

        stderr.write("\r")
    var downloadedFileHash = calculateFileSha3(pendingPath)
    if downloadedFileHash != remoteHash:
        stderr.writeLine("Hash mismatch for " & path)
        stderr.writeLine("  remote catalog: " & remoteHash)
        stderr.writeLine("  downloaded    : " & downloadedFileHash)
        discard tryRemoveFile(pendingPath)
        quit(-1)
    return some(path)


proc getUnwritablePaths(paths: seq[string]): seq[string] =
    var unwritablePaths: seq[string]
    for path in paths:
        try:
            var f = open(path, fmAppend)
            close(f)
        except:
            unwritablePaths.add(path)
    return unwritablePaths

proc waitFilesWriteable(paths: seq[string]): bool =
    var waitTimeSeconds: int = filesWritableCheckTimeout
    const retryIntervalSeconds: int = 5
    while waitTimeSeconds > 0:
        var unwritablePaths: seq[string] = getUnwritablePaths(paths)
        if len(unwritablePaths) == 0:
            return true
        stderr.writeLine("locked files: " & $unwritablePaths)
        stderr.writeLine("   retring in " & $retryIntervalSeconds & " seconds")
        sleep(1000 * retryIntervalSeconds)
        waitTimeSeconds -= retryIntervalSeconds
    return false

proc runUpdate(isVerbose: bool): int =
    var url = getRemoteUrl(catalogFilename)
    if isVerbose:
        echo("Checking update at " & url)
    else:
        echo("Checking updates...")
    #var remoteCatalogContent = puppy.fetch(url)
    var remoteCatalogContent = retry[CurlError, string](proc():string = return ncurlFetch(url),
            max_tries=10, sleep_time_sec=5)
    var remoteSignatureConent = retry[CurlError, string](proc():string = return ncurlFetch(getRemoteUrl(signatureFilename)),
            max_tries=10, sleep_time_sec=5)
    var remoteSignature = loadSignatureString(remoteSignatureConent)
    if not verifyStringSignature(remoteCatalogContent, remoteSignature):
        stderr.writeLine(url & " signature verification failed")
        return -1
    var pendingUpdates: seq[string]
    for remoteHash, path, index, total in iterateCatalog(remoteCatalogContent):
        var filePending = downloadRemoteFile(remoteHash, path, index, total, isVerbose)
        if filePending.isSome():
            pendingUpdates.add(filePending.get())

    if len(pendingUpdates) > 0 and not waitFilesWriteable(pendingUpdates):
        stderr.writeLine("Exiting due to locked files. Update not applied, no files changed.")
        return -1

    for updatedFilePath in pendingUpdates:
        var pendingPath = getPendingPath(updatedFilePath)
        os.moveFile(pendingPath, updatedFilePath)

    # some extra spaces to overwrite leftover characters from progress print
    echo("All files are up to date.                                                                                                        ")
    return 0

proc cmdLineUpdateCatalog(): int =
    if not fileExists(getKeypairPath()):
        stderr.writeLine("ERROR: " & getKeypairPath() & " does not exist")
        stderr.writeLine("Run '" & getExecutableFilename() & " keygen' to generate a keypair")
        return -1
    var kp = loadEdsyncKeypair(getKeypairPath())
    var nItems = createCatalog(getIgnoreRules())
    echo("Created catalog file: " & catalogFilename & " with " & $nItems & " files.")
    signCatalog(kp)
    echo("Signed catalog file: " & signatureFilename)
    return 0

proc cmdLineKeygen(): int =
    var path = getKeypairPath()
    if fileExists(path):
        echo(path & " already exists. Aborting.")
        return -1
    saveEdsyncKeypair(genKeypair(), path)
    echo("Created " & path)
    return 0

proc cmdLineMakeSourceJson(url: string): int =
    var kp = loadEdsyncKeypair(getKeypairPath())
    saveSourceJson(kp.publicKey, url)
    echo("Created " & edsyncSourceFilename)
    return 0

when isMainModule:
    var p = newParser:
        help("edsync " & version & ": simple http file sync")
        command("update-catalog"):
            help("Create " & catalogFilename & " & " & signatureFilename)
            run:
                quit(cmdLineUpdateCatalog())
        command("make-source-json"):
            help("Create " & edsyncSourceFilename & " with pubkey & url.")
            arg("url")
            run:
                quit(cmdLineMakeSourceJson(opts.url))
        command("keygen"):
            help("Create public & private keys at " & getKeypairPath())
            run:
                quit(cmdLineKeygen())
        command("update"):
            help("[DEFAULT] Update local files based on " & edsyncSourceFilename)
            flag("-v", "--verbose")
            run:
                quit(runUpdate(opts.verbose))
    try:
        if len(commandLineParams()) == 0:
            var updateResult = runUpdate(false)
            var startTime = epochTime()
            while startTime + 5 > epochTime() and getPressedKey() == -1:
                sleep(1)
            quit(updateResult)
        else:
            p.run(commandLineParams())
    except UsageError:
        stderr.writeLine getCurrentExceptionMsg()
        quit(-1)
