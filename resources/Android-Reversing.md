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

## Tools you'll need for the job
- adb
- zipalign
- apksigner
    - [android-studio](https://developer.android.com/studio) (this comes with all tools above)
- [apktool](https://apktool.org)
- keytool
- jarsigner 
    - you should have these* natively installed if you have JDK, but if you don't.. install your latest Java JDK

### Theory
 Before we start taking apart our android phone, we need to understand the system's architecture
![Architecture](../assets/images/android-reversing/android-architecture.png)
Source -> [https://mobisec.reyammer.io/slides](https://mobisec.reyammer.io/slides)

### Android apps do not have a single entry point, but rather multiple depending on user actions. AKA there is no "main"
### These are the objects that contain entry points based off particular actions
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
ation for the first time. They persist even after phone restart unless the user 
manually disables them.

* Content Provider 
An abstact layer that handles retrieval and trasmission of data from the app's d
atabase. Usually these databases are structured as an SQLite

* Intents 
When applications want their components/other applications to communicate with each other, they can
 use this special class to initiate the protocol. The data that is sent using an Intent is called a Bundle.
|
|
|
- Explicit -> specifies the exact full package name of the component that it wants to communicate to
- Implicit -> a generic intent that can be picked up by any other avaliable service.


Each version of android is identified by a number known as an "API level"
If an app requires a minimum API level of, say, 31, then your android build
will have to be an API level >= !

Most apps will have their minimum API level set pretty low relative to the latest version, but 
they will also provide information on what API version they were designed for.

### Android's Managers

Shown in the picture above, Android is built off of the Linux core. However, when there are certain syscalls requesting 
sensitive/special information that is device-specific, such as your smartphone, android uses a special 
component called a "Manager" that resides in the userspace

An example would be your phone's app location - something that is exclusive to your phone
An app would invoke the android api through this manager, but while doing so, would still be within the sandbox due to the "Manager" also being in userspace. Manager tends to behave
like its own app, but with slightly higher privileges due to containing sensitive data.

Behind the scenes, this interprocess communication is administered by a IPC/RPC called Binder
Intents are defined by binder calls, so Apps use them when they want to communicate with these "Managers", and really any other app.

And with IPC/RPC communication, a special device driver that uses ioctl transfers communication between the userspace-unprivileged and the
userspace-privileged
See image below, and here's more information on what a [device driver](https://en.wikipedia.org/wiki/Device_driver) if you're starting fresh.

![RPC](../assets/images/android-reversing/android-RPC.png)
Source -> [https://mobisec.reyammer.io/slides](https://mobisec.reyammer.io/slides)

* * * 

## Using ADB

Our first tool for teh job is called ADB. It essentially lets you interact with the component so that you 


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


Text can be **bold**, _italic_, ~~strikethrough~~ or `keyword`.

[Link to another page](./another-page.html).

There should be whitespace between paragraphs.

There should be whitespace between paragraphs. We recommend including a README, or a file with information about your project.

# Header 1

This is a normal paragraph following a header. GitHub is a code hosting platform for version control and collaboration. It lets you and others work together on projects from anywhere.

## Header 2

> This is a blockquote following a header.
>
> When something is important enough, you do it even if the odds are not in your favor.

### Header 3

```js
// Javascript code with syntax highlighting.
var fun = function lang(l) {
  dateformat.i18n = require('./lang/' + l)
  return true;
}
```

```ruby
# Ruby code with syntax highlighting
GitHubPages::Dependencies.gems.each do |gem, version|
  s.add_dependency(gem, "= #{version}")
end
```

#### Header 4

*   This is an unordered list following a header.
*   This is an unordered list following a header.
*   This is an unordered list following a header.

##### Header 5

1.  This is an ordered list following a header.
2.  This is an ordered list following a header.
3.  This is an ordered list following a header.

###### Header 6

| head1        | head two          | three |
|:-------------|:------------------|:------|
| ok           | good swedish fish | nice  |
| out of stock | good and plenty   | nice  |
| ok           | good `oreos`      | hmm   |
| ok           | good `zoute` drop | yumm  |

### There's a horizontal rule below this.

* * *

### Here is an unordered list:

*   Item foo
*   Item bar
*   Item baz
*   Item zip

### And an ordered list:

1.  Item one
1.  Item two
1.  Item three
1.  Item four

### And a nested list:

- level 1 item
  - level 2 item
  - level 2 item
    - level 3 item
    - level 3 item
- level 1 item
  - level 2 item
  - level 2 item
  - level 2 item
- level 1 item
  - level 2 item
  - level 2 item
- level 1 item

### Small image

![Octocat](https://github.githubassets.com/images/icons/emoji/octocat.png)

### Large image

![Branching](https://guides.github.com/activities/hello-world/branching.png)


### Definition lists can be used with HTML syntax.

<dl>
<dt>Name</dt>
<dd>Godzilla</dd>
<dt>Born</dt>
<dd>1952</dd>
<dt>Birthplace</dt>
<dd>Japan</dd>
<dt>Color</dt>
<dd>Green</dd>
</dl>

```
Long, single-line code blocks should not wrap. They should horizontally scroll if they are too long. This line should be long enough to demonstrate this.
```

```
The final element.
```

Custom javascript


