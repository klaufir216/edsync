import strutils
import std/tables
import std/strformat
import os
import libcurl

when defined(ncurltest):
    import retry
    import humanbytes

const 
    curlCaBundleFilename: string = "curl-ca-bundle.crt"

type
  CurlError* = object of IOError

type
  RequestInfo = object
    session: PCurl
    url: string
    statusLine: string
    responseHeaders: OrderedTable[string, string]
    dataCallback: proc(session: PCurl, buffer: string)
    headerCallback: proc(headers: OrderedTable[string, string])
    progressCallback: proc(current: int, total: int)

proc curlHeaderFunction(
  buffer: cstring,
  size: int,
  count: int,
  RequestInfoPtr: pointer
): int {.cdecl.} =
    if size != 1:
        raise newException(CurlError, "OPT_HEADERFUNCTION: Unexpected curl write callback size: " & $size)
    let reqInfo = cast[ptr RequestInfo](RequestInfoPtr)
    if reqInfo == nil:
        return
    var headerLine: string = ""
    headerLine.setLen(count)
    copyMem(headerLine[0].addr, buffer, count)
    headerLine = headerLine.strip()
    if headerLine.endsWith("\c\L"):
        headerLine = headerLine[0..^3]
    # echo ( "Header line: '" & headerLine.strip() & "'")

    if headerLine == "":
        if reqInfo.headerCallback != nil:
            reqInfo.headerCallback(reqInfo.responseHeaders)
        return count

    if reqInfo.statusLine == "":
        reqInfo.statusLine = headerLine
    else:
        var headerKeyVal = headerLine.split(": ",1 )
        var headerKey = headerKeyVal[0]
        var headerValue = headerKeyVal[1]
        reqInfo.responseHeaders[headerKey.toLower()] = headerValue
    return count

proc curlWriteFunction(
  buffer: cstring,
  size: int,
  count: int,
  RequestInfoPtr: pointer
): int {.cdecl.} =
    if size != 1:
        raise newException(CurlError, "Unexpected curl write callback size")
    let reqInfo = cast[ptr RequestInfo](RequestInfoPtr)
    
    if reqInfo == nil or reqInfo.dataCallback == nil:
        return

    var sBuffer: string = ""
    sBuffer.setLen(count)
    copyMem(sBuffer[0].addr, buffer, count)
    
    var http_code: clong
    var session = reqInfo.session
    discard session.easy_getinfo(INFO_RESPONSE_CODE, addr http_code)
    if http_code != 200 and http_code != 206:
        raise newException(CurlError, "http code " & $http_code)

    reqInfo.dataCallback(reqInfo.session, sBuffer)
    return count

proc curlProgressFunction(
    RequestInfoPtr: pointer,
    dltotal: cdouble,
    dlnow: cdouble,
    ultotal: cdouble,
    ulnow: cdouble): int {.cdecl.} =
    let reqInfo = cast[ptr RequestInfo](RequestInfoPtr)
    if reqInfo.progressCallback != nil:
        reqInfo.progressCallback(int(dlnow), int(dltotal))
    return 0
        
proc curlRequest*(
    http_method: string,
    url: string,
    onDataCallback: proc(session: PCurl, buffer: string),
    requestHeaders: OrderedTable[string, string] = initOrderedTable[string,string](),
    onHeaderCallback: proc(responseHeaders: OrderedTable[string, string]) = nil,
    onProgressCallback: proc(current:int, total: int) = nil ) =
    let curl = libcurl.easy_init()
    var ri = RequestInfo(
        session: curl,
        url: url,
        responseHeaders: initOrderedTable[string, string](),
        dataCallback: onDataCallback,
        headerCallback: onHeaderCallback,
        progressCallback: onProgressCallback)
    
    assert http_method == "GET" or http_method == "HEAD", "only GET and HEAD supported"
        
    
    if curl == nil:
        raise newException(CurlError, "easy_init() failed")

    if http_method == "HEAD":
        discard curl.easy_setopt(OPT_NOBODY, 1);

    discard curl.easy_setopt(OPT_URL, url.cstring)
    
    if fileExists(curlCaBundleFilename):
        # echo("using " & curlCaBundleFilename)
        discard curl.easy_setopt(OPT_CAINFO, curlCaBundleFilename.cstring)
    else:
        # echo("using embedded CA bundle")
        var caInfoBlob = curl_blob(data: curlCaBundle.cstring, len: len(curlCaBundle))
        discard curl.easy_setopt(OPT_CAINFO_BLOB, caInfoBlob)
    
    
    # struct curl_slist *list = NULL;
    # list = curl_slist_append(list, "Shoesize: 10");
    # list = curl_slist_append(list, "Accept:");
    # curl_slist_free_all(list);
    #
    var headerSlist: ptr Slist = nil
    for (k,v) in requestHeaders.pairs():
        var headerLine: string = k & ": " & v
        headerSlist = slist_append(headerSlist, headerLine.cstring)
    
    if headerSlist != nil:
        discard curl.easy_setopt(OPT_HTTPHEADER, headerSlist);
        #defer: slist_free_all(headerSlist)
    

    # send all accept-encodings supported by curl
    # on windows the embedded curl version supports "deflate, gzip, br, zstd"
    # on linux it depends on the system curl, on Ubuntu 20.04: "deflate, gzip, br"
    discard curl.easy_setopt(OPT_ENCODING, "".cstring)
    
    # OPT_TIMEOUT sets the maximum amount a curl function can execute
    # it is NOT read timeout; even when data is still flowing
    # the function will abort when the timeout is exceeded
    discard curl.easy_setopt(OPT_TIMEOUT, 0)
    
    discard curl.easy_setopt(OPT_CONNECTTIMEOUT, 10)
    
    # abort if slower than 1024 bytes/sec for 10 seconds
    discard curl.easy_setopt(OPT_LOW_SPEED_TIME, 1024);
    discard curl.easy_setopt(OPT_LOW_SPEED_LIMIT, 10);
    
    discard curl.easy_setopt(OPT_WRITEFUNCTION, curlWriteFunction)
    discard curl.easy_setopt(OPT_WRITEDATA, addr ri)

    # header callback
    discard curl.easy_setopt(OPT_HEADERFUNCTION, curlHeaderFunction)
    discard curl.easy_setopt(OPT_HEADERDATA, addr ri)
    
    # no ctrl-c handler
    # discard curl.easy_setopt(OPT_NOSIGNAL, 1)

    if onProgressCallback != nil:
        discard curl.easy_setopt(OPT_PROGRESSFUNCTION, curlProgressFunction)
        discard curl.easy_setopt(OPT_PROGRESSDATA, addr ri)
        discard curl.easy_setopt(OPT_NOPROGRESS, false)

    # automatically follow HTTP 304 redirects
    discard curl.easy_setopt(OPT_FOLLOWLOCATION, 1)

    # verbose off
    discard curl.easy_setopt(OPT_VERBOSE, 0)

    let easyPerformResultCode = curl.easy_perform()
    if headerSlist != nil:
        slist_free_all(headerSlist)
    if easyPerformResultCode != libcurl.E_OK:
        raise newException(CurlError, $libcurl.easy_strerror(easyPerformResultCode))


proc ncurlDownload*(url: string, output_filename: string, onProgress: proc(current:int, total: int)=nil) =
    var filesize: BiggestInt = 0
    if fileExists(output_filename):
        filesize = getFileSize(output_filename)

    var fd = open(output_filename, fmAppend)
    defer: fd.close()

    proc onData(session: PCurl, buffer: string) =
        fd.write(buffer)

    var requestHeaders = initOrderedTable[string,string]()
    if filesize > 0:
        requestHeaders["Range"] = fmt"bytes={filesize}-"
        #requestHeaders["Range"] = "bytes=" & $filesize & "-"

    try:
        curlRequest("GET", url, 
            onDataCallback=onData, 
            requestHeaders=requestHeaders,
            onHeaderCallback=nil, 
            onProgressCallback=onProgress)
    except CurlError as e:
        # hack: when the file is complete ignore 416 (unsatisfiable range) on a retry
        if e.msg == "http code 416":
            return
        raise

proc ncurlFetch*(url: string): string =
    var r: string = ""
    proc onData(session: PCurl, buffer: string) =
        r &= buffer
    curlRequest("GET", url, 
        onDataCallback=onData, 
        onHeaderCallback=nil)
    return r

when defined(ncurltest):
    if isMainModule:
        var url = paramStr(1)
        let url_filename = url.split('/')[^1]
        proc onProgress(current:int, total: int) =
            if total > 0:
                var msg = fmt"{url_filename}: {humanBytes(current)} / {humanBytes(total)}"
                stderr.write(fmt"{msg:<79}" & "\r")

        var output_filename = "output.bin"
        retryVoid[CurlError](proc() = ncurlDownload(url, output_filename, onProgress), 
            max_tries=10, sleep_time_sec=5)
        echo ""
        echo retry[CurlError, string](proc():string = return ncurlFetch("https://icanhazip.com"), 
            max_tries=10, sleep_time_sec=5)
