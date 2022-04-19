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

const catalogFilename = "edsync-catalog.sha3"
const signatureFilename = "edsync-catalog.sig"
const edsyncSourceFilename = "edsync-source.json"
const edsyncSignerKeypairFilename = ".edsync-signer-keypair"
const edsyncIgnoreFilename = ".edsyncignore"
const pendingPathPostfix = ".edsync-pending"
const filesWritableCheckTimeout = 60

proc getIgnoreRules(): seq[string] =
    if fileExists(edsyncIgnoreFilename):
        return readFile(edsyncIgnoreFilename).strip().split('\n')
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

proc loadSignatureFile(): Signature =
    return loadSignatureString(readFile(signatureFilename))

proc loadSourceJsonPublicKey(): PublicKey =
    var pk: PublicKey
    var jobj = parseJson(readFile(edsyncSourceFilename))
    var pkStr = base64.decode(jobj["public_key"].getStr())
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

proc createCatalog(ignoreRules: seq[string]): int =
    result = 0
    var catalogFile: File = open(catalogFilename, fmWrite)
    defer: close(catalogFile)
    for filenameConst in os.walkDirRec("./"):
        var filename: string = filenameConst
        filename = filename.replace("\\", "/")
        removePrefix(filename, "./")
        if any(ignoreRules, proc (rule: string): bool = filename.matches(rule)):
            echo("Ignored : " & filename)
            continue
        if filename == catalogFilename or
           filename == edsyncSourceFilename or
           filename == signatureFilename or
           filename == getExecutableFilename():
            continue
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

iterator iterateCatalog(catalogContent: string): tuple[hash: string, path: string] =
    var lines = catalogContent.split("\n")
    for line in lines:
        var temp: seq[string] = line.split(" *", maxsplit=1)
        if len(temp) != 2:
            continue
        var catalogHash = temp[0]
        var path = temp[1]
        if os.isAbsolute(path):
            stderr.writeLine("Catalog: Skipping absolute path: " & path)
            continue
        if ".." in path:
            stderr.writeLine("Catalog: Skipping path with '..': " & path)
            continue
        yield (catalogHash, path)

proc verifyLocalCatalog(): bool = 
    result = true
    var signature = loadSignatureFile()
    var catalogContent = readFile(catalogFilename)
    if not verifyStringSignature(catalogContent, signature):
        stderr.writeLine("FAILURE: Signature verification error.")
        result = false
    
    for hash, path in iterateCatalog(catalogContent):
        if hash != calculateFileSha3(path):
            stderr.writeLine("FAILURE: Hash mismatch for file: '" & path & "'")
            result = false

proc getRemoteUrl(path: string): string =
    return $(parseUri(loadSourceJsonUrl()) / path)

proc getPendingPath(path: string): string =
    path & pendingPathPostfix

proc downloadRemoteFile(remoteHash: string, path: string): Option[string] =
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
        echo("Already downloaded: " & path)
    else:
        # echo("Downloading: " & path)
        #var pendingContent = puppy.fetch(getRemoteUrl(path), progressCallback=progressCallback)
        #echo ""
        #var pendingFile: File = open(pendingPath, fmWrite)
        #pendingFile.write(pendingContent)
        #close(pendingFile)
        #retryVoid[CurlError](proc() = ncurlDownload(url, output_filename), 
        #    max_tries=10, sleep_time_sec=5)
        #var url = getRemoteUrl(path)
        #let url_filename = url.split('/')[^1]
        proc onProgress(current:int, total: int) =
            if total > 0:
                var msg = fmt"{path}: {humanBytes(current)} / {humanBytes(total)}"
                stderr.write(fmt"{msg:<79}" & "\r")

        retryVoid[CurlError](proc() = ncurlDownload(getRemoteUrl(path), pendingPath, onProgress), 
            max_tries=10, sleep_time_sec=5)

        stderr.write("\n")
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

proc runUpdate(): int = 
    var url = getRemoteUrl(catalogFilename)
    echo("Checking update at " & url)
    #var remoteCatalogContent = puppy.fetch(url)
    var remoteCatalogContent = retry[CurlError, string](proc():string = return ncurlFetch(url), 
            max_tries=10, sleep_time_sec=5)
    echo("remote catalog content")
    echo(remoteCatalogContent)
    #var remoteSignatureConent = puppy.fetch(getRemoteUrl(signatureFilename))
    var remoteSignatureConent = retry[CurlError, string](proc():string = return ncurlFetch(getRemoteUrl(signatureFilename)), 
            max_tries=10, sleep_time_sec=5)
    var remoteSignature = loadSignatureString(remoteSignatureConent)
    if not verifyStringSignature(remoteCatalogContent, remoteSignature):
        stderr.writeLine(url & " signature verification failed")
        quit(-1)
    var updatedFilePaths: seq[string]
    for remoteHash, path in iterateCatalog(remoteCatalogContent):
        var filePending = downloadRemoteFile(remoteHash, path)
        if filePending.isSome():
            updatedFilePaths.add(filePending.get())

    if len(updatedFilePaths) == 0:
        echo("All files up-to-date. Exiting")
        return 0

    if not waitFilesWriteable(updatedFilePaths):
        stderr.writeLine("Exiting due to locked files. Update not applied, no files changed.")

    for updatedFilePath in updatedFilePaths:
        var pendingPath = getPendingPath(updatedFilePath)
        os.moveFile(pendingPath, updatedFilePath)

    var catalogFile: File = open(catalogFilename, fmWrite)
    defer: close(catalogFile)
    catalogFile.write(remoteCatalogContent)
    saveSignature(remoteSignature)
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

proc cmdLineVerify(): int =
    if verifyLocalCatalog():
        echo "SUCCESS: Local catalog signature & content verified."
        return 0
    return -1

proc cmdLineMakeSourceJson(url: string): int =
    var kp = loadEdsyncKeypair(getKeypairPath())
    saveSourceJson(kp.publicKey, url)
    echo("Created " & edsyncSourceFilename)
    return 0

when isMainModule:
    if len(commandLineParams()) == 0:
        quit(runUpdate())
    var p = newParser:
        help("{prog}: Sync signed files on HTTP")
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
        command("verify"):
            help("Verify files based on " & catalogFilename)
            run:
                quit(cmdLineVerify())
        command("update"):
            help("[DEFAULT] Update local files based on " & edsyncSourceFilename)
            run:
                quit(runUpdate())
    try:
        p.run(commandLineParams())
    except UsageError as e:
        stderr.writeLine getCurrentExceptionMsg()
        quit(-1)
