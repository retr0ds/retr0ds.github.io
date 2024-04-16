---
title: Android Reversing - Basic Setup
date: 2022-02-19 22:00:00
summary: This covers basic android reversing that I did in my freshman year
tags: ["Writeup", "Android", "PicoCTF"]
defaultBackgroundImage: img/background.svg
---


## Week 1(13th Feb 2022-18th Feb 2022)


Started with android reversing, went through few writeups and videos. Attempted to solve  hayyim ctf 2022 breakable.apk, failed to fathom the code, so started off with solving droids-series from pico ctf
### New Tools learned
* d2j-dex2jar-to convert the apk to its java archive
`d2j-dex2jar filename.apk -o filename.jar`

* apktool-to extract the resources and the smali code
`apktool d filename.apk -o foldername`
* jd-gui-to view the graphical disassembly of the jar file
`jd-gui filename.jar`
* Also used android studio to emulate the apk
### Challenges solved
#### picoCTF 
- [x] droids0-involved looking at the event log in android studio and ctrl+f for "pico"
- [x] droids1-involved finding the if condition ,taking the resource number used in .get() to find the pasword, we see is stored in "password" string, looking under "password" in strings.xml ..."opossum" gets us the flag 
- [x] droids2-involved assembling pieces of a string stored as an array in a particular order("dismass.ogg.weatherwax.aching.nitt.garlick") to get flag

## Week 2(20th Feb 2022-25th Feb 2022)
Continued with last week's learning and started with understanding hwo to patch a apk.For this I looked into droids3 and droids4 from pico ctf.
### New Tools learned

* keytool - Generate a new key to sign the build
`keytool -genkeypair -v -keystore key.keystore -alias publishingdoc -keyalg RSA -keysize 2048 -validity 10000`
*  jarsigner - to sign the apk after patching it
`jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore ./key.keystore <path to apk>.apk publishingdoc`
### Challenges solved
#### picoCTF
- [x] droids3-involved patching the smali code from moving to "nope" function to "yep" function for any input given
- [ ] droids4-