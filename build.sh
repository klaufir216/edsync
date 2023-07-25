#!/bin/sh

nim c -d:noSignalHandler -d:release -d:strip --opt:size updater.nim
