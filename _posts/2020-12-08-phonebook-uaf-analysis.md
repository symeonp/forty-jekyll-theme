---
layout: post
title: Discovery and analysis of a Windows PhoneBook Use-After-Free vulnerability (CVE-2020-1530)
description: A step-by-step tutorial and analysis of a Windows vulnerability.
image: assets/images/rasapi-header.png
---


<h2>Introduction</h2>

Back in April I started browsing the MSDN with the purpose of finding a file format that it's not very common, it has not
been fuzzed in the past, it is available on every modern Windows version, and thus something that will give me good chances
to find a bug. After spending a few hours, I bumped into this lovely <a href="https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumentriesa">RasEnumEntriesA</a>[1] API:

<img src="{{site.url}}/assets/images/rasenumentries.png">


So hold on a minute, what's a phone-book (pbk) file?!

From <a href="https://docs.microsoft.com/en-us/windows/win32/rras/ras-phone-books">here</a>, we can see:


<blockquote>

Phone books provide a standard way to collect and specify the information that the Remote Access Connection Manager needs to establish a remote connection. Phone books associate entry names with information such as phone numbers, COM ports, and modem settings. Each phone-book entry contains the information needed to establish a RAS connection.

Phone books are stored in phone-book files, which are text files that contain the entry names and associated information. RAS creates a phone-book file called RASPHONE.PBK. The user can use the main Dial-Up Networking dialog box to create personal phone-book files. The RAS API does not currently provide support for creating a phone-book file. Some RAS functions, such as the RasDial function, have a parameter that specifies a phone-book file. If the caller does not specify a phone-book file, the function uses the default phone-book file, which is the one selected by the user in the User Preferences property sheet of the Dial-Up Networking dialog box.

</blockquote>


Excellent! That's exactly what I was looking for. In the rest of this article we will dive into the Windows PhoneBook API and proceed with finding samples, creating a harness, checking coverage
and finally fuzz this API in order to discover vulnerabilities.


<h2>Getting Samples</h2>

Since I wasn't familiar at all with the phone book file format, a quick search yielded a few sample file formats:


<img src="{{site.url}}/assets/images/pbk_samples.png" width="800" height="500">

A sample file format looks like that:

{% highlight VisualBasic %}

[SKU]
Encoding=1
PBVersion=4
Type=2
AutoLogon=0
UseRasCredentials=1
LowDateTime=688779312
HighDateTime=30679678
DialParamsUID=751792375
-- snip --
AuthRestrictions=512
IpPrioritizeRemote=1
IpInterfaceMetric=0
IpHeaderCompression=0
IpAddress=0.0.0.0
IpDnsAddress=0.0.0.0
IpDns2Address=0.0.0.0
IpWinsAddress=0.0.0.0
IpWins2Address=0.0.0.0

NETCOMPONENTS=
ms_msclient=1
ms_server=1

MEDIA=rastapi
Port=VPN1-0
Device=WAN Miniport (PPTP)

DEVICE=vpn
PhoneNumber=vpn.sku.ac.ir
AreaCode=
CountryCode=0
CountryID=0
UseDialingRules=0
Comment=
FriendlyName=
LastSelectedPhone=0
PromoteAlternates=0
TryNextAlternateOnFail=1
{% endhighlight %}


<h2>Finding attack surface</h2>

As a second step I've quickly grabbed a few samples and experimented a bit. It turns out Windows ships already with an executable living in the system32 directory called <b>rasphone.exe</b> which also gives you a lot of interesting parameters with their description:

<img src="{{site.url}}/assets/images/rasphone_binary.png">

Now the next step is to make sure that we are indeed hitting the <b>RasEnumEntries</b> function... You can probably use a few of the Windows API
Monitoring tools, I'll go with classic WinDbg way and just set a breakpoint :)

<pre>
0:000> bp RASAPI32!RasEnumEntriesA
0:000> bp RASAPI32!RasEnumEntriesW
</pre>

In case you haven't noticed there's a <i>'Note'</i> at the very bottom of the page:

<blockquote>
The ras.h header defines RasEnumEntries as an alias which automatically selects the ANSI or Unicode version of this function based on the definition of the UNICODE preprocessor constant. Mixing usage of the encoding-neutral alias with code that not encoding-neutral can lead to mismatches that result in compilation or runtime errors. For more information, see Conventions for Function Prototypes.
</blockquote>

In short, the RasEnumEntriesA uses the ANSI version comparing to the RasEnumEntriesW where is using wide strings (Unicode).

After loading the file by running <code>windbg.exe rasphone.exe -f sample.pbk</code> we can observe the following:

<img src="{{site.url}}/assets/images/bp_hit.png">

Bingo! Looking at the stack backtrace it is clear that the rasphone binary calls the <code>RASDLG</code> API (a dialog wrapper around the RASAPI32 API) and
then eventually we hit our target (<code>RasEnumEntriesW</code>). So far so good!

<h2>Creating the harness</h2>

This is the juicy part of this blog post! If you have been watching <a href="https://twitter.com/gamozolabs?lang=en">@gamozolabs</a>' streams you know that fuzzing is all about creating decent harnesses and exploring the right path codes!
Where do we begin then? Well, for our good luck the previous link to <b>RasEnumEntriesA</b> documentation Microsoft provided us with a decent <a href="https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumentriesa">example</a> (MSDN and github can be your friends!).
Reading the sample code, we need to call two times the <b>RasEnumEntries</b> function, one to get the required buffer size and
another one which actually performs the real call with the right parameters. The sample is also missing a very important argument,
the second parameter to the RasEnumEntries function is NULL, and thus "the entries are enumerated from all the remote access phone-book files in the AllUsers profile and the user's profile". Let's fix that:

{% highlight C %}

// RasEntries.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include "ras.h"
#include "raserror.h"
#pragma comment(lib, "rasapi32.lib")


int main(int argc, char** argv)
{
    DWORD dwCb = 0;
    DWORD dwRet = ERROR_SUCCESS;
    DWORD dwErr = ERROR_SUCCESS;
    DWORD dwEntries = 0;
    LPRASENTRYNAME lpRasEntryName = NULL;
    DWORD rc;
    DWORD dwSize = 0;
    LPCSTR lpszPhonebook = argv[1];
    DWORD dwRasEntryInfoSize = 0;

    RASENTRY* RasEntry = NULL;      // Ras Entry structure
    BOOL bResult = TRUE;    // return for the function
    RasEntry = (RASENTRY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        sizeof(RASENTRY));

    printf("main: %p\n", (void*)main);

    if (argc < 2) {
        printf("Usage: %s <bpk file>\n", argv[0]);
        return 0;
    }

    // Call RasEnumEntries with lpRasEntryName = NULL. dwCb is returned with the required buffer size and 
    // a return code of ERROR_BUFFER_TOO_SMALL
    dwRet = RasEnumEntriesA(NULL, lpszPhonebook, lpRasEntryName, &dwCb, &dwEntries);

    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        // Allocate the memory needed for the array of RAS entry names.
        lpRasEntryName = (LPRASENTRYNAME)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);
        if (lpRasEntryName == NULL) {
            wprintf(L"HeapAlloc failed!\n");
            return 0;
        }
        // The first RASENTRYNAME structure in the array must contain the structure size
        lpRasEntryName[0].dwSize = sizeof(RASENTRYNAME);

        // Call RasEnumEntries to enumerate all RAS entry names
        dwRet = RasEnumEntries(NULL, lpszPhonebook, lpRasEntryName, &dwCb, &dwEntries);

        // If successful, print the RAS entry names 
        if (ERROR_SUCCESS == dwRet) {

            printf("Number of Entries %d\n", dwEntries);
            wprintf(L"The following RAS entry names were found:\n");

            for (DWORD i = 0; i < dwEntries; i++) {
                printf("%s\n", lpRasEntryName[i].szEntryName);
            }

        }
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasEntryName);
        lpRasEntryName = NULL;
    }


    return 0;
}

{% endhighlight %}


Let's compile the above code and run it with our sample file:

<img src="{{site.url}}/assets/images/initial_ms.png">


Excellent! I've gone ahead and measured the code coverage (see next section) with this initial harness which unfortunately
it's not very impressive. As such, the next step was to slight try to add 1-2 more functions within the RASAPI32 API as to increase
code coverage as well as the chances to discover a bug! After a lot of trial and error and looking at the github repos the final harness looks like this:


<img src="{{site.url}}/assets/images/final_harness_code.png">


Here, I have added the <code>RasValidateEntryName</code> and the <code>RasGetEntryProperties</code> functions. Running the final version with another file sample resulted in the following screenshot:


<img src="{{site.url}}/assets/images/final_harness.png">


<h2>Exploring Code Coverage</h2>

With the harness ready and with our samples lying around, I quickly coded this python snippet to automate the process of getting the DynamoRIO
files via drcov:

{% highlight python %}
import subprocess
import glob

samples = glob.glob("C:\\Users\\simos\\Desktop\\pbk_samples\\*")

for sample in samples:
	harness = "C:\\pbk_fuzz\\RasEntries.exe %s test" % sample
	command = "C:\\DRIO79\\bin32\\drrun.exe -t drcov -- %s" % harness
	print "[*] Running harness %s with sample %s" % (harness, command) 	 
	p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	print out
	print err
{% endhighlight %}

The above simple script gave me the following output:

<img src="{{site.url}}/assets/images/coverage_python.png">

Notice the drcov *.log files produced by DynamoRIO. I've simply loaded the RASAPI32.dll within BinaryNinja and used the lightouse plugin (for more information please see my <a href="https://symeonp.github.io/2017/09/17/fuzzing-winafl.html">previous tutorial</a>)


<img src="{{site.url}}/assets/images/rasapi_coverage.png">

From the screenshot above it can be observed that the coverage is only less than 10%. Ideally, you'd expect the file samples to at least be
able to exercise 20% of the module. Nevertheless I decided to move on and see if I get lucky.


<h2>Fuzzing it</h2>


With the final harness and our samples together and having measured some basic code coverage now it's the time to actually go ahead and fuzz it. For this compaign I've used two different techniques,
one was winafl and the other one was a very simple fuzzing framework I have coded which is simply a wrapper around radamsa and winappdbg to
monitor and save the crashes. I have had really success in the past  with winafl, however when it comes to targets such as text-based format parsing, winafl unfortunately is not very effective.

For this campaign I've used a fully updated Windows 7 x64 VM (from Microsoft Dev before they change it to Windows 10 only versions)
as many times I encountered few issues with DynamoRIO not being able to get proper coverage from miscellaneous Windows DLLs (even though I had
recompiled winafl with latest DynamoRIO myself). While we are here, I can't emphasise how this trick has saved me so many times:

<b>Disable ASLR!</b>

<img src="{{site.url}}/assets/images/disable_aslr.png">
<div class="box">
<b>Protip</b>: ASLR will randomise offsets and generally will mess up things - as such when I'm fuzzing I always find it much more easier to disable it and have a static address
pointing to <code>main()</code> or <code>my_target()</code>. 
</div>

Next let's quickly run winafl with the previously obtained address:

<code>afl-fuzz.exe -i Y:\samples -o Y:\pbk_fuzz -D Y:\DRIO7\bin32\ -t 20000 -- -target_module RasEntries.exe -coverage_module RASAPI32.dll -target_offset 0x01090 -fuzz_iterations 2000 -nargs 2 -- Y:\RasEntries.exe @@</code>

.. and let winafl do it all for you! Here, I simply instrumented winafl to target my harness (<code>RasEntries.exe</code>) and for coverage use the <code>RASAPI32.dll</code> DLL. Here are the results after just three days of fuzzing:

<img src="{{site.url}}/assets/images/rasapi_fuzzing.png">


W00t! Quite a lot of crashes with 25 being "unique"! It should be noted here that I managed to pretty much get the first crash within half an hour of fuzzing...few interesting observations:

<ul>
        <li>I stopped the fuzzer while it was <b>still</b> finding new paths due to the fact it kept hitting the same bug again and again.</li>
        <li>The speed was pretty much decent in the beginning (> 100 exec/s) which however dropped during more path discovery.</li>
        <li>Stability is < 90%. Perhaps the consumed memory is not properly cleaned up?</li>
</ul>


At this phase I'd also like to mention that running a simple fuzzer such as radamsa I was literally able to get crashes within <b>seconds</b>:

<img src="{{site.url}}/assets/images/radamsa_crashes.png">


<h2>Crash triage</h2>

<img src="{{site.url}}/assets/images/pbk_crashes.png">

As you can see from the screenshot above the crashers' size is pretty much the same which indicates that we might be hitting the same bug again and again. After automating the process with BugId, it turns that the 25 "unique" bugs were actually
the same case!


<h2>Vulnerability Analysis</h2>

With the harness ready and our crasher alive and kicking let's run it under the debugger:

<img src="{{site.url}}/assets/images/uaf-stack-trace.png">

With page heap enabled and stack trace (<b>gflags.exe /i binary +hpa +ust</b>), notice how we're hitting a second chance crash.
The crash occured in the <code>wcsstr</code> function:

<blockquote>
Returns a pointer to the first occurrence of strSearch in str, or NULL if strSearch does not appear in str. If strSearch points to a string of zero length, the function returns str.
</blockquote>

which was also called within RASAPI32's <code>ReadEntryList</code> function. We are trying to dereference the value pointed by <code>edx</code> which according to page verification is invalid.
In fact, trying to get more information regarding the memory address stored in the <code>edx</code> register we can indeed see that is value has been previously freed! Wonderful! This clearly is the case of a use-after-free vulnerability, as somehow this memory has been freed, yet the <code>wcsstr</code>
function tried to access that part of memory. Now let's try to actually pinpoint the issue!

For this step I had to switch between the old windbg and the new preview (since the preview was not very reliable when I wanted to examine the free'd memory).
Let's start by examining the free'd allocation:


<img src="{{site.url}}/assets/images/free_callee.png">

We can derive from above that at 0x7214936c the  RASAPI32!CopyToPbport+0x00000064 is responsible for freeing the memory.
After doing an Unassemble (ub), the instructions look as follows:

    72149361 7409            je      RASAPI32!CopyToPbport+0x64 (7214936c)
    72149363 ff770c          push    dword ptr [edi+0Ch]
    72149366 ff159ca01672    call    dword ptr [RASAPI32!_imp__GlobalFree (7216a09c)]

Let's restart windbg and set up a breakpoint:

    0:000> ?72149366 - RASAPI32
    Evaluate expression: 693094 = 000a9366
    0:000> bp RASAPI32+000a9366

Here I'm calculating the offset from RASAPI32's base module (we won't be able to hit exact offset since it gets rebased due to ASLR)

<img src="{{site.url}}/assets/images/memory_alloc.png">

As expected the memory breakpoint was hit. We are just before free'ing that memory, and from the disassembly we can see
the <b>KERNELBASE!GlobalFree</b> function gets only one parameter: 

    push    dword ptr [edi+0Ch]

To double confirm it we can check the available MSDN documentation from <a href="https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree">here</a>:

<blockquote>
 HGLOBAL GlobalFree(
  _Frees_ptr_opt_ HGLOBAL hMem
);
</blockquote>    


There are a few more interesting bits to notice here, the value of the allocated buffer is <b>0x2a</b>.
This is very important as we need to know whether is value is user controlled or not. How many bytes is this one?

    0:000> ?2a
    Evaluate expression: 42 = 0000002a

So the initial allocated buffer is 42 bytes. Moving on, which function called this allocation?

    0:000> ub 721355f8 
    RASAPI32!StrDupWFromAInternal+0x1a:
    721355dd 50              push    eax
    721355de 53              push    ebx
    721355df ff15bca11672    call    dword ptr [RASAPI32!_imp__MultiByteToWideChar (7216a1bc)]
    721355e5 8945fc          mov     dword ptr [ebp-4],eax
    721355e8 8d044502000000  lea     eax,[eax*2+2]
    721355ef 50              push    eax
    721355f0 6a40            push    40h
    721355f2 ff15a4a01672    call    dword ptr [RASAPI32!_imp__GlobalAlloc (7216a0a4)]


After doing some basic reverse engineering, we can see that within RASAPI32's <b>StrDupWFromAInternal</b> function, the <a href="https://docs.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar">MultiByteToWideChar</a> is initially called, and then depending on the length of the string, <b><a href="https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc">GlobalAlloc</a></b> is called with the following
two parameters:

    DECLSPEC_ALLOCATOR HGLOBAL GlobalAlloc(
      UINT   uFlags,
      SIZE_T dwBytes
    );

The first one is the static value 0x40 which is uFlags, which according to the documentation:

<div class="table-wrapper">
    <table>
        <tbody>
            <tr>
                <td><b>GMEM_ZEROINIT</b><p>0x0040</p> </td>
                <td>Initializes memory contents to zero</td>
        </tr>
    </tbody>
</table>
</div>

The second parameter is the previously calculated string length:


<img src="{{site.url}}/assets/images/buffer_alloc1.png">


Let's have a closer look right before the allocation:

    0:000> dc edi
    0019f07c  314e5056 0000302d 00000000 00000000  VPN1-0..........
    0019f08c  00000000 00000000 00000000 00000000  ................
    0019f09c  00000000 00000000 00000000 00000000  ................
    0019f0ac  00000000 00000000 00000000 00000000  ................
    0019f0bc  00000000 00000000 00000000 00000000  ................
    0019f0cc  00000000 00000000 00000000 00000000  ................
    0019f0dc  00000000 00000000 00000000 00000000  ................
    0019f0ec  00000000 00000000 00000000 00000000  ................
    0:000> p
    eax=00000007 ebx=0000fde9 ecx=c8a47ecb edx=00000007 esi=00000000 edi=0019f07c
    eip=721355e8 esp=0019f048 ebp=0019f058 iopl=0         nv up ei pl zr na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
    RASAPI32!StrDupWFromAInternal+0x25:
    721355e8 8d044502000000  lea     eax,[eax*2+2]
    0:000> 
    eax=00000010 ebx=0000fde9 ecx=c8a47ecb edx=00000007 esi=00000000 edi=0019f07c
    eip=721355ef esp=0019f048 ebp=0019f058 iopl=0         nv up ei pl zr na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
    RASAPI32!StrDupWFromAInternal+0x2c:
    721355ef 50              push    eax
    0:000> 
    eax=00000010 ebx=0000fde9 ecx=c8a47ecb edx=00000007 esi=00000000 edi=0019f07c
    eip=721355f0 esp=0019f044 ebp=0019f058 iopl=0         nv up ei pl zr na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
    RASAPI32!StrDupWFromAInternal+0x2d:
    721355f0 6a40            push    40h
    0:000> 
    eax=00000010 ebx=0000fde9 ecx=c8a47ecb edx=00000007 esi=00000000 edi=0019f07c
    eip=721355f2 esp=0019f040 ebp=0019f058 iopl=0         nv up ei pl zr na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
    RASAPI32!StrDupWFromAInternal+0x2f:
    721355f2 ff15a4a01672    call    dword ptr [RASAPI32!_imp__GlobalAlloc (7216a0a4)] ds:002b:7216a0a4={KERNELBASE!GlobalAlloc (76a2f000)}
    0:000> dds esp L2
    0019f040  00000040   <== uFlags
    0019f044  00000010   <== dwBytes

So as seen above the length of the <b>"VPN1-0"</b> phone book entry is 6+1, which is user controlled, and once it gets multiplied times two and gets added with two,
it's then used as a parameter to the <b>GlobalAlloc</b> method. So brilliant, we definitely  control this one!

However, what caused the free? After spending some time, I figured out that the issue was this entry within the phonebook:

<img src="{{site.url}}/assets/images/the_bug.png">

Aha! So a malformed entry causes the StrDupWFromAInternal to bail out and free the memory!

<h2>Exploitation</h2>

Now that we have a basic understanding of the vulnerability here are my thoughts regarding exploitation
of this issue - take it with a grain of salt!
Let's start with the following minimised PoC:

    [CRASH]
    Encoding=1
    PBVersion=4
    Type=2

    MEDIA=rastapiPort=VPN1
    Device=AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD

    DEVICE=vpn
    PhoneNumber=localhost
    AreaCode=
    CountryCode=0
    CountryID=0
    UseDialingRules=0
    Comment=
    FriendlyName=
    LastSelectedPhone=0
    PromoteAlternates=0
    TryNextAlternateOnFail=1


Based on our previous analysis we expect to see <b>eax</b> having the length of the device input "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"+1 = 33 (<b>0x21</b>) bytes:

<img src="{{site.url}}/assets/images/buffers.png">

Fantastic, our assumption is correct! And what about the <b>actual</b> allocation?


    eax=00000021 ebx=0000fde9 ecx=1184fd4b edx=00000021 esi=00000000 edi=0019f07c
    eip=721355e8 esp=0019f048 ebp=0019f058 iopl=0         nv up ei pl zr na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
    RASAPI32!StrDupWFromAInternal+0x25:
    721355e8 8d044502000000  lea     eax,[eax*2+2]
    0:000> p
    eax=00000044 ebx=0000fde9 ecx=1184fd4b edx=00000021 esi=00000000 edi=0019f07c
    eip=721355ef esp=0019f048 ebp=0019f058 iopl=0         nv up ei pl zr na pe nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246


As seen previously the final value would be <b>eax*2+2</b> meaning: <b>0x44 bytes</b>.


<img src="{{site.url}}/assets/images/alloc_free.png">

Notice above that after monitoring the allocs/frees, we can see that the memory allocator rounded
the initial value to <b>0x48</b>, then three more allocs are happening and then eventually the address is being reused.

Ultimately, we need to find out a way to somehow replace the freed object with something with same size.


<h2>Conclusion</h2>

Although we do have a usually exploitable primitive such as a use-after-free, unfortunately in reality the lack of a scripting
environment makes it very difficult - feel free to prove me wrong! I don't think there's an easy method to manipulate the objects, nor mess with the allocators/deallocators.
Nevertheless, perhaps someone with more skills is able to find a way to accomplish that.

I hope you enjoyed this article and learnt something - I certainly did!

<h2>Disclosure Timeline</h2>

<div class="table-wrapper">
	<table>
		<tbody>
			<tr>
				<td>27 April 2020 </td>
				<td>Initial report to Microsoft.</td>
			</tr>
			<tr>
				<td>11 August 2020</td>
				<td>Microsoft issued <a href="https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1530">CVE-2020-1530</a> for this vulnerability.</td>
			</tr>
			<tr>
				<td>11 August 2020</td>
				<td>Microsoft acknowledged this issue as Elevation of Privilege Vulnerability with a CVSS score of 7.8</td>
			</tr>
			<tr>
				<td>11 August 2020</td>
				<td>Microsoft released a fix (Patch Tuesday).</td>
			</tr>
		</tbody>
	</table>
</div>


<h2>References</h2>

<ol>
<li>RasEnumEntries Documentation: https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumentriesa</li>
<li>Sample Phonebook File for a Demand-dial Connection documentation: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/65a59781-dfc5-4e9c-a422-3738d1fc3252</li>
</ol>