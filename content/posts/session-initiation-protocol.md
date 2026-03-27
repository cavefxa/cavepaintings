---
title: "Breaking the Session Initiation Protocol in IMS Networks"
date: 2026-03-26T10:49:00+02:00
description: "Samsung IMS reversing journey - instrumenting imsservice.apk and libsec-ims.so to capture, edit, and replay SIP traffic against live 4G IMS networks"
---

# Table of Contents

- [Preface and Disclaimer](#preface-and-disclaimer)
- [Background](#background)
    + [What is SIP?](#what-is-sip)
- [Reversing](#reversing)
    + [imsservice.apk](#imsservice.apk)
    + [libsec-ims.so](#libsec-ims.so)
        + [A better hook](#a-better-hook)
- [Results](#results)
- [Conclusion](#conclusion)

# Preface and Disclaimer
Almost a year ago I was finishing my bachelor's degree. At the time, I was working as a penetration tester at a Danish telecommunications company, so I wanted to write a thesis that was relevant to my workplace. After speaking with colleagues, I decided to experiment with the Session Initiation Protocol, better known as SIP. This article walks through the methodology, background, and results of the tests.

None of the work done here represents the opinions of my former employer. All impacted parties have been anonymized to avoid leaking information about potentially still vulnerable systems.

# Background
The Session Initiation Protocol (SIP) is best known as the signaling core of IP telephony, or Voice over IP (VoIP). Many tools exist for exercising SIP on legacy VoIP stacks, but equivalent utilities for Voice over LTE (VoLTE) are scarce even though 4G networks rely on VoLTE for voice services. Because I could not be sure the research would uncover vulnerabilities, I focused the thesis on closing this tooling gap. The article will not discuss the tooling, only the research.

## What is SIP?
The Session Initiation Protocol (SIP) is a cornerstone protocol in telecommunications networks. It initiates, maintains, and terminates communication sessions. The Internet Engineering Task Force developed SIP, submitting the initial draft in 1997, releasing the second version in 1998, and promoting it to Proposed Standard status as RFC 2543 in March 1999.

SIP is a plain-text protocol that borrows ideas from the Hypertext Transfer Protocol (HTTP) and the Simple Mail Transfer Protocol (SMTP). From HTTP it inherits the client/server design and the use of Uniform Resource Identifiers (URIs) and Uniform Resource Locators (URLs), while from SMTP it adopts headers such as `From:` and `Subject:`.

Consider a simplified example of communication between two parties in a VoIP environment where both devices know each other's addresses:

{{< figure src="/pictures/call.png" alt="VoIP call example" width="60%" >}}

William wants to talk to Emil, so he opens his dialing app and places a call. William's phone sends an `INVITE` to Emil, and Emil's phone responds with `Ringing`. When Emil picks up, it returns `200 OK`, William acknowledges with `ACK`, and a media session is established. SIP handles the signaling only, while separate protocols negotiate and carry the media.

Below is a simple SIP request:
```
INVITE sip:emil@voip.phone.org; phone-context=voip.phone.org; SIP/2.0
Via: SIP/2.0/UDP voip.phone.org:5060; branch=z9hG4bK
Max-Forwards: 70
To: emil <sip:emil@voip.phone.org>
From: william <sip:william@voip.phone.org>; tag=12345
Call-ID: 123456789X-cave
CSeq: 1 INVITE
Contact: <sip:william@voip.phone.org>
Content-Type: application/sdp
Content-Length: ...
```

This snippet highlights several key SIP headers. The `To` header names the intended recipient, while `From` identifies the originator and includes a unique dialog tag. `Call-ID` carries a random identifier that keeps the dialog unique, and `Contact` specifies where follow-up requests should be sent. Finally, the message includes `Content-Type` and `Content-Length` headers, just like HTTP, that precede the SDP (Session Description Protocol) payload, which negotiates the media parameters. If the IMS network fails to validate headers such as `From`, attackers can exploit the gap for caller ID spoofing by forging the number that appears on the recipient's phone.

The diagram below highlights several of the important aspects of the SIP flow:
{{< figure src="/pictures/volte-simplified.png" alt="Simplified SIP flow" width="60%" >}}


# Reversing 
To replicate the SIP flow that a phone follows, I built a few small hooks to alter the behavior of an IMS implementation on a rooted Samsung S20 (SM-G780G). After pushing a Frida server to the device's `/data/local/tmp` folder, I began by identifying the relevant files. Two components immediately stood out during the filesystem walk: `imsservice.apk` and `libsec-ims.so`, representing the Java service and the associated native library.

## imsservice.apk
I used `frida-trace` to watch the function calls that occur during phone communications. One standout function inside `imsservice.apk` is `makeCall`, and `jadx-gui` shows the snippet below:

![](/pictures/jadx-makecall.png)

The function mostly logs through a `StringBuilder`, but the call tree reveals this invocation flow:

![](/pictures/invocation.png)

The function `processCommandBuffer` is a native function called through the Java Native Interface (JNI). It resides in `libsec-ims.so` and is responsible for communicating with the HAL (Hardware Abstraction Layer), which sends the request to the baseband processor and ultimately to the nearest cell tower.

The function `makeMakeCall` turned out to be responsible for constructing most of the `INVITE`.
![](/pictures/makemakecall.png)

![](/pictures/createstring.png)

Because `createString` uses a standard UTF-8 encoder, inserting CRLF characters into the display name lets us append new headers beneath it. That trick became the first way I modified the `INVITE` request.

{{< figure src="/pictures/injected.png" alt="Injected" width="70%" >}}

This setup is enough to send basic `INVITE` requests, but flying blind gets frustrating fast.

## libsec-ims.so
Running Ghidra with `JNIAnalyzer` for JNI typing produced the decompilation below:

![](/pictures/ghidra.png)

The JNI call `CallStaticVoidMethod` hands control to Java so response data can travel from the native
layer back into the runtime. That mechanism lets `processMessage` deliver the populated byte array to
Java. Decompiling the original APK reveals the Java-side method:

![](/pictures/processmessage.png)

By hooking the Java-side `processMessage` and converting the byte array to ASCII, we can analyze the SIP requests and responses. Below is the trace of a message where the originating phone number was changed to `+4513371337`:

![](/pictures/siptrace.png)

The same hook works even without modifying the requests.

### A better hook
Crafting SIP messages from scratch required more reversing. Many of the shared object's methods live
in the `resip` namespace from the open-source
[resiprocate project](https://github.com/resiprocate/resiprocate).

Tracing and logging inside Frida revealed the following invocation flow:
`StartSession -> SendInvite -> SendSipMsg -> SendSipToNW`.

`BaseManager::SendSipToNW(int, resip::SipMessage const&, TransactionUserHandler*)` uses IPC to communicate with the HAL. The argument contains an object of type `resip::SipMessage`. 

Every C++ class with virtual methods gets a virtual method table (vtable) that stores pointers to those methods. When we only have a `SipMessage*` at runtime, we can still jump to helper functions as long as we know the right offsets inside its vtable. That is why mapping the vtable layout matters. Using `clang` we can inspect the vtable:

```
clang++ -c testSipMessage.cxx -I/usr/include/c++/v1 \
    -Xclang -fdump-vtable-layouts -I/tmp/resiprocate
```

It looks as follows:
```
Vtable for 'resip::SipMessage' (11 entries).
   0 | offset_to_top (0)
   1 | resip::SipMessage RTTI
       -- (resip::Message, 0) vtable address --
       -- (resip::SipMessage, 0) vtable address --
       -- (resip::TransactionMessage, 0) vtable address --
   2 | resip::SipMessage::~SipMessage() [complete]
   3 | resip::SipMessage::~SipMessage() [deleting]
   4 | resip::Message::Brief resip::Message::brief() const
   5 | resip::Message *resip::SipMessage::clone() const
   6 | std::ostream &resip::SipMessage::encode(std::ostream &) const
   7 | std::ostream &resip::SipMessage::encodeBrief(std::ostream &) const
   8 | const resip::Data &resip::SipMessage::getTransactionId() const
   9 | bool resip::SipMessage::isClientTransaction() const
  10 | std::ostream &resip::SipMessage::encodeSipFrag(std::ostream &) const
```

The most helpful entry is `resip::Message *resip::SipMessage::clone()`. Once we hold a `SipMessage`
object, we can call helper methods such as:
```c
void
SipMessage::addHeader(Headers::Type header, const char* headerName, int headerLen, 
   const char* start, int len)

/* ... */

void
SipMessage::remove(const ExtensionHeader& headerName)
```

Once the hook works, we can lean on the `SipMessage` helpers to add or remove headers and craft
arbitrary requests. The earlier `clang++` command used the upstream `resiprocate` source, so the
vtable offsets might differ from Samsung's build. That left two options: locate the `clone` entry in
the device binary or experiment with offsets until one worked. Trial and error showed that the `clone`
method sat at `2 * Process.pointerSize` inside the vtable. 

Because `SipMessage::addHeader` takes a `Headers::Type` enum, I mirrored it in the Frida script so the
hook could rewrite outgoing SIP requests. Below is a slightly scuffed Frida hook that modifies SIP
traffic (including non-INVITE requests) and demonstrates the approach:

```javascript
const globals = []; // used to ensure our allocated strings don't despawn

const targetModule = "libsec-ims.so";
const targetFunction = "_ZN11BaseSession11SendSipToNWERKN5resip10SipMessageEP22TransactionUserHandler"; // function sending sip over network

var singleton = 0;
const singleton_disabled = true;

const SipHeaders = {
    UNKNOWN: -1, Via: 0, MaxForwards: 1, Route: 2, RecordRoute: 3, Path: 4, ServiceRoute: 5, ProxyRequire: 6, ProxyAuthenticate: 7, Identity: 8, IdentityInfo: 9, Require: 10, Contact: 11, To: 12, From: 13, CallID: 14,
    CSeq: 15, Subject: 16, Expires: 17, SessionExpires: 18, MinSE: 19, Accept: 20, AcceptEncoding: 21, AcceptLanguage: 22, AlertInfo: 23, Allow: 24, AuthenticationInfo: 25, CallInfo: 26, ContentDisposition: 27, ContentEncoding: 28, ContentId: 29,
    ContentLanguage: 30, ContentTransferEncoding: 31, ContentType: 32, Date: 33, ErrorInfo: 34, InReplyTo: 35, MinExpires: 36, MIMEVersion: 37, Organization: 38, SecWebSocketKey: 39, SecWebSocketKey1: 40, SecWebSocketKey2: 41, Origin: 42,
    Host: 43, SecWebSocketAccept: 44, Cookie: 45, Priority: 46, ProxyAuthorization: 47, ReplyTo: 48, RetryAfter: 49, FlowTimer: 50, Server: 51, SIPETag: 52, SIPIfMatch: 53, Supported: 54, Timestamp: 55, Unsupported: 56, UserAgent: 57,
    Warning: 58, WWWAuthenticate: 59, SubscriptionState: 60, ReferTo: 61, ReferredBy: 62, Authorization: 63, Replaces: 64, Event: 65, AllowEvents: 66, SecurityClient: 67, SecurityServer: 68, SecurityVerify: 69, RSeq: 70,
    RAck: 71, Reason: 72, Privacy: 73, RequestDisposition: 74, PMediaAuthorization: 75, Join: 76, TargetDialog: 77, PAssertedIdentity: 78, PPreferredIdentity: 79, AcceptContact: 80, RejectContact: 81, PCalledPartyId: 82, PAssociatedUri: 83, ContentLength: 84,
    ReferSub: 85, AnswerMode: 86, PrivAnswerMode: 87, RemotePartyId: 88, HistoryInfo: 89, PAccessNetworkInfo: 90, PChargingVector: 91, PChargingFunctionAddresses: 92, PVisitedNetworkID: 93, UserToUser: 94, MAX_HEADERS: 95, NONE: 96
};

function removeSipMessageHeader(sipMessagePtr, headerType) {
    const removeMethodPtr = Module.findExportByName(targetModule, "_ZN5resip10SipMessage6removeENS_7Headers4TypeE");
    const removeMethod = new NativeFunction(removeMethodPtr, "void", ["pointer", "int"]);
    
    removeMethod(sipMessagePtr, headerType);
    
    return true;
}

function addSipMessageHeader(sipMessagePtr, headerType, headerName, headerValue) {
    const addMethodPtr = Module.findExportByName(targetModule, "_ZN5resip10SipMessage9addHeaderENS_7Headers4TypeEPKciS4_i");
    const addMethod = new NativeFunction(addMethodPtr, "void", ["pointer", "int", "pointer", "int", "pointer", "int"]);
    
    globals.push(Memory.allocUtf8String(headerName));
    globals.push(headerName.length);

    globals.push(Memory.allocUtf8String(headerValue));
    globals.push(headerValue.length);

    addMethod(
        sipMessagePtr,
        headerType,
        globals[globals.length - 4],
        globals[globals.length - 3],
        globals[globals.length - 2],
        globals[globals.length - 1]
    );
    
    return true;
}

function cloneSipMessage(sipMessagePtr) {
    const vtablePtr = Memory.readPointer(sipMessagePtr);
    const cloneFuncPtr = Memory.readPointer(vtablePtr.add(2 * Process.pointerSize));
    
    const cloneFunc = new NativeFunction(cloneFuncPtr, "pointer", ["pointer"]);
    const newSipMessagePtr = cloneFunc(sipMessagePtr);
    
    return newSipMessagePtr;
}

const baseSessionSendSipToNW = Module.findExportByName(targetModule, targetFunction);
if (baseSessionSendSipToNW) {
    Interceptor.attach(baseSessionSendSipToNW, {
        onEnter(args) {
            if (!singleton || singleton_disabled) { 
              singleton = 1; 

              const originalSipMessagePtr = args[1];

              const clonedSip = cloneSipMessage(originalSipMessagePtr);
              removeSipMessageHeader(clonedSip, SipHeaders.MaxForwards);
              addSipMessageHeader(clonedSip, SipHeaders.MaxForwards, "Max-Forwards", "69");
              addSipMessageHeader(clonedSip, SipHeaders.UNKNOWN, "Bogus-Header", "cave"); // unknown for not used

              args[1] = clonedSip;
            }
        },
        onLeave(retval) {
        }
    });
} else {
    console.log(`[-] Failed to find ${targetFunction}`);
}

setTimeout(function() {
  Java.perform(function () {
    let StackIF = Java.use("com.sec.internal.ims.core.handler.secims.StackIF");
    
    const MESSAGE_TYPES = {
      INVITE: 3848,
      CANCEL: 2444,
      RINGING: 1032,
      SESSION_PROGRESS: 1829,
      TRYING: 604,
      DNE: 596,
      BYE: 816
    };
    
    StackIF.processMessage.implementation = function (bArr, i) {
      let printed = false;
      
      if (bArr != null) {
        if (i == MESSAGE_TYPES.CANCEL || 
            i == MESSAGE_TYPES.RINGING || 
            i == MESSAGE_TYPES.SESSION_PROGRESS || 
            i == MESSAGE_TYPES.TRYING || 
            i == MESSAGE_TYPES.DNE || 
            i == MESSAGE_TYPES.BYE || 
            i == MESSAGE_TYPES.INVITE || 
            i > 0) {
          
          let res = byteArrayToReadableString(bArr).split("\n");
          let skipProcessing = false;
          
          res.forEach(function(element) {
            if (skipProcessing) return;
            
            let match = element.match(/([A-Z].+)$/);
            if (match && match.length > 1) {
              let cleanedElement = match[1];
              
              if (cleanedElement.includes("Content-Length")) {
                skipProcessing = true; // only display one content-length per segment, everything after indicates the smuggled part
              }
              
              if (cleanedElement.includes("SIP") || cleanedElement.includes("sip") || cleanedElement.includes(": ")) {
                console.log(`Type: ${i} : ${cleanedElement}`);
                printed = true;
              }
            }
          });
        }
      
        if (printed === true) {
          console.log("\n");
        }
        
        return this.processMessage(bArr, i);
      }
      
      return this.processMessage(bArr, i);
    };
    
    function byteArrayToReadableString(byteArray) {
      let result = "";
      for (let i = 0; i < byteArray.length; i++) {
        const byte = byteArray[i] & 0xff;
        if (byte >= 32 && byte <= 126) {
          result += String.fromCharCode(byte);
        } else if (byte == 0x0a) {
          result += "\n";
        }
      }
      return result;
    }
    
    console.log("[+] Java hooks for StackIF successfully installed");
  });
}, 500);
```

# Results
I discovered multiple undocumented vulnerabilities in Danish telecommunication infrastructure:

- **Caller ID spoofing across several providers.** By manipulating the `From` header, I could spoof caller IDs at multiple operators, as shown below. Effectiveness varied per carrier, and my previous employer's network ignored the spoofed `From` header ;) - rendering the network *safe* against this attack.

{{< figure src="/pictures/spoof1.png" alt="Injected" width="40%" >}}
{{< figure src="/pictures/spoof2.png" alt="Injected" width="40%" >}}

- **Pseudo-deanonymization via an IVR system.** A Danish taxi company's IVR performed an address lookup based on the caller's phone number, effectively exposing where and when that number last ordered a taxi.

- **Data smuggling for free connectivity.** Because SIP `INVITE` messages are free to send, the header space can be abused to shuttle low-bandwidth data between devices. For example, a traveler without free roaming could send `INVITE` messages to a phone on their home Wi-Fi, receive the requested data in SIP headers, and read it locally.

- **Denial of service on a Pixel 8A.** Certain crafted messages consistently broke call reception on a Pixel 8A test device, indicating a crash or lockup condition.

**All vulnerabilities were responsibly disclosed to the impacted parties prior to May 2025. They (said they) initiated internal investigations toward fixes.**


# Conclusion
Future development could address the current limitations through:
- Extending support to additional device models and IMS implementations. Modifying an open-source phone OS, such as LineageOS, to fully control the IMS stack might also be possible.
- Revisiting the `Alert-Info` header to see whether ringtone spoofing (for example, a forced rickroll) can be made reliable.
- Investigating SIP compression features as a potential attack surface.

These findings reinforce how important it is to harden SIP stacks across telecommunications infrastructure. *And most importantly how fun it is to break systems!*
