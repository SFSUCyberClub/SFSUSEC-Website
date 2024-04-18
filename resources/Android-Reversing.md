---
layout: default
title: Android Reversing
description: "by devilmanCr0" 
---

# Welcome to Android 101 Reverse engineering

After spending some time reviewing powerful tools to reverse engineer Android applications, I thought it would be nice
to share this knowledge. I haven't been able to find good resources on debugging non-rooted phones, so in this guide, I will
be providing further information on parts _others have left out_

There are many open source tools on github, and I implore you learn more about them (as should i :P) - but for now, please try setting up the environment manually. I will try to create a docker image providing all the tools at some point.

For the sake of simplicity and fundementals, we will spend time reverse engineering Doodle Jump - ever heard of it? You play as a
jumping platformer that you can control with your phone's gyroscope. The goal is to get as high up as you can.

## Tools you'll need for the job
- adb
- zipalign
- apksigner
    - [android-studio](https://developer.android.com/studio) (this comes with all tools above)
- [apktool](https://apktool.org)
- keytool
- jarsigner 
    - you should have these* natively installed if you have a Java JDK
- bettercap (optional)
- Frida
    - pip install Frida


### Theory
 Before we start taking apart our android phone, we need to understand the system's architecture
![Architecture](../assets/images/android-reversing/android-architecture.png)
Source -> [https://mobisec.reyammer.io/slides](https://mobisec.reyammer.io/slides)

### Android apps do not have a single entry point, but rather multiple depending on user actions. AKA there is no "main".
### The following are objects that contain entry points based off particular actions.
### Every object type also has a life cycle that is clearly defined by google's smoogles [documentation](https://developer.android.com/guide/components/activities/activity-lifecycle)

* Activity  
When the user interacts with the app in any way defined by the GUI, the activity
 class can be launched to deal with its request

* Service 
A background process running regardless of user interaction. This could be anyth
ing that does not need to run in the foreground

* Broadcast Receiver
Whenever there is a broadcasted event issued by android, the app can receive it 
and respond to it using this object class that defines what action needs to be p
erformed during such event. They are initialized when the user starts the applic
ation for the first time. They persist even after the phone restarts unless the user 
manually disables them.

* Content Provider 
An abstact layer that handles retrieval and trasmission of data from the app's database.
Usually these databases are structured with SQLite.

* Intents 
When applications want their components/other applications to communicate with each other, they can
 use this special class to initiate the protocol. The data that is sent using an Intent is called a Bundle.
|
|
|
- Explicit -> specifies the exact full package name of the component that it wants to communicate to
- Implicit -> a generic intent that can be picked up by any other avaliable service.
Intents are used in almost all components of an app, so this one's especially important.

Each version of android is identified by a number known as an "API level"
If an app requires a minimum API level of, say, 31, then your android build
will have to be an API level >= !

Most apps will have their minimum API level set pretty low relative to the latest version, but 
they will also provide information on what API version they were designed for - known as the target API.

### Android's Managers

Shown in the picture above, Android is built off of the Linux core. However, when there are certain syscalls requesting 
sensitive/special information that is device-specific, such as your smartphone, android uses a special 
component called a "Manager" that resides in the userspace

An example would be your phone's app location - something that is exclusive to your phone's capability of obtaining.
An app would invoke the android api through this manager, but while doing so, would still be within the sandbox due to the "Manager" also being in userspace. Manager tends to behave
like its own app, but with slightly higher privileges.

Behind the scenes, this interprocess communication is administered by a IPC/RPC called Binder
Intents are defined by binder calls, so Apps use them when they want to communicate with these "Managers", and really any other app.

And with IPC/RPC communication, a special device driver in the kernel uses ioctl to administer communication between the userspace-unprivileged and the userspace-privileged
See image below, and here's more information on what a [device driver](https://en.wikipedia.org/wiki/Device_driver) is if you're starting fresh.

![RPC](../assets/images/android-reversing/android-RPC.png)
Source -> [https://mobisec.reyammer.io/slides](https://mobisec.reyammer.io/slides)

* * * 

With some of these fundementals out of the way, let's get started with retrieving Doodle Jump from our phone. 
>> Make sure to enable USB debugging in the [developer settings](https://developer.android.com/studio/debug/dev-options)
>> Make sure to use a USB Micro cable with a data line

## Using ADB

Our first tool for teh job is called ADB. Integrated by Google for app developers, this tool allows you to interface between your
device and host machine. We can use ADB to our advantage when we want to retrieve, install, or modify apps. Since we're going to be taking apart an app from the phone, we're going to use `adb pull` to retrieve it.

Before we do that, however, we should first find where it's located within our phone's filesystem.
- Run `adb shell pm list packages` to list the full package name of each app registered on your android.
  - Use `grep` so that you can filter down this list to the specific app you are looking for.
- Run `adb shell pm path <package name>` to acquire the full path

Once you have the full path, you'll see a 'base.apk' file at the end of it. This is quite literally your app, so go ahead and
`adb pull <path of package> .` and you should be ready for the next step!

_Note for future reference_ - If for some reason you mysteriously encounter a "no such file or directory error" despite properly addressing the path, you may want to try entering your android's shell with `adb shell`, copying the base.apk elsewhere (like /sdcard/) (while you're in the android shell) `adb cp <original path of base.apk> /sdcard/`, and trying `adb pull` again with the new path.

## The Framework of an app

As we seen from the image above, an app is mostly comprised of java bytecode and c++ native libraries that the android system
can understand and run. Let's talk about what apps are formatted in - APK

An apk is essentially just a zipped package, you can extract all of its raw contents using
unzip base.apk -d yourappsnamehere

You'll find familiar names, but everything is going to be mangled so we'll need to use another tool for the job... 

* /assests/*
Usually contains the app's sprites or media to be preseted

* /res/*
sometimes its custom styles etc

* /resources.arsc
maps the resources to a numerical identify for the app to use

* /classes.dex
contains bytecode for the app that is the heart of the application
usually compiled in java or kotlin, does not matter

* /libs/
contents to execute native code, usually compiled in C or C++ for game engines or various
other applications. ELF formatted and organized based off architecture.

* /META-INF/
A certificate folder in order to verify the validity and authenticity of the app before being able
to be installed on an android's system

* MANIFEST.MF file with SHA-1 or SHA-256 hashes for all files inside the apk
* CERF.SF file, similar to MANIFEST.MF but signed with a RSA key instead
* CERT.RSA file containing public key to sign apps and be verified by CERT.SF

You can use openssl like so to read more information about the public key
openssl pkcs7 -in META-INF/CERT.RSA -inform DER -print

this will tell you more about the issuer of the RSA key

Apps need to be signed for author integrity. You can think of the thing that's signing them as 
a certificate, but only issued and validated by the author of the apk.


## Using ApkTool

ApkTool allows you to unzip apk packages while retaining the contents in human-readable form.

### Uncompress using ApkTool




