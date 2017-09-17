---
layout: post
title: Fuzzing the MSXML6 library with WinAFL
description: A walkthrough using WinAFL.
image: assets/images/msxml_fuzz.png
---


<h2>Introduction</h2>
In this blog post, I'll write about how I tried to fuzz the MSXML library using the <a href="https://github.com/ivanfratric/winafl">WinAFL</a> fuzzer.

If you haven't played around with WinAFL, it's a massive fuzzer created by Ivan (Google's Project Zero) based on the <a href="http://lcamtuf.coredump.cx/afl/">lcumtuf's AFL</a>
which uses DynamoRIO to measure code coverage and the Windows API for memory and process creation.
<a href="https://twitter.com/0vercl0k">Axel Souchet</a> has been activily contributing features such as <a href="https://github.com/ivanfratric/winafl/commit/691dc760690750752054794891f75fbce50fee56">corpus minimization</a>, latest afl stable builds, <a href="https://github.com/ivanfratric/winafl/commit/8aa1e138dd0284b1da5c844c5d21fc5ebe5d1c45">persistent execution mode</a> which will cover on the next blog post and the finally the <a href="https://github.com/ivanfratric/winafl/commit/992a68ba34df152e07453f0b592ff79aa8d4de9a">afl-tmin</a> tool.

We will start by creating a test harness which will allow us to fuzz some parsing functionality within the library,
calculate the coverage, minimise the test cases and finish by kicking off the fuzzer and triage the findings.
Lastly, thanks to <a href="https://twitter.com/mkolsek">Mitja Kolsek</a> from <a href="https://0patch.com">0patch</a> for prividing the patch which will see how one can use the 0patch to patch this issue!

Using the above steps, I've managed to find a NULL pointer dereference on the <code>msxml6!DTD::findEntityGeneral</code> function,
which I reported to Microsoft but got rejected as this is not a security issue. Fair enough, indeed the crash is crap, yet
hopefully somebody might find interesting the techiniques I followed!


<h2>The Harness</h2>
While doing some research I ended up on <a href="https://msdn.microsoft.com/en-us/library/ms754517(v=vs.85).aspx">this</a> page which Microsoft has kindly provided a sample C++ code which allows us to feed some XML files and validate its structure.
I am going to use Visual Studio 2015 to build the following program but before I do that, I am slightly going to modify it
and use Ivan's <a href="https://github.com/ivanfratric/winafl/blob/master/gdiplus.cpp#L29">charToWChar</a> method so as to accept an argument as a file:

{% highlight C %}
// xmlvalidate_fuzz.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#import <msxml6.dll>
extern "C" __declspec(dllexport)  int main(int argc, char** argv);

// Macro that calls a COM method returning HRESULT value.
#define CHK_HR(stmt)        do { hr=(stmt); if (FAILED(hr)) goto CleanUp; } while(0)

void dump_com_error(_com_error &e)
{
    _bstr_t bstrSource(e.Source());
    _bstr_t bstrDescription(e.Description());

    printf("Error\n");
    printf("\a\tCode = %08lx\n", e.Error());
    printf("\a\tCode meaning = %s", e.ErrorMessage());
    printf("\a\tSource = %s\n", (LPCSTR)bstrSource);
    printf("\a\tDescription = %s\n", (LPCSTR)bstrDescription);
}

_bstr_t validateFile(_bstr_t bstrFile)
{
    // Initialize objects and variables.
    MSXML2::IXMLDOMDocument2Ptr pXMLDoc;
    MSXML2::IXMLDOMParseErrorPtr pError;
    _bstr_t bstrResult = L"";
    HRESULT hr = S_OK;

    // Create a DOMDocument and set its properties.
    CHK_HR(pXMLDoc.CreateInstance(__uuidof(MSXML2::DOMDocument60), NULL, CLSCTX_INPROC_SERVER));

    pXMLDoc->async = VARIANT_FALSE;
    pXMLDoc->validateOnParse = VARIANT_TRUE;
    pXMLDoc->resolveExternals = VARIANT_TRUE;

    // Load and validate the specified file into the DOM.
    // And return validation results in message to the user.
    if (pXMLDoc->load(bstrFile) != VARIANT_TRUE)
    {
        pError = pXMLDoc->parseError;

        bstrResult = _bstr_t(L"Validation failed on ") + bstrFile +
            _bstr_t(L"\n=====================") +
            _bstr_t(L"\nReason: ") + _bstr_t(pError->Getreason()) +
            _bstr_t(L"\nSource: ") + _bstr_t(pError->GetsrcText()) +
            _bstr_t(L"\nLine: ") + _bstr_t(pError->Getline()) +
            _bstr_t(L"\n");
    }
    else
    {
        bstrResult = _bstr_t(L"Validation succeeded for ") + bstrFile +
            _bstr_t(L"\n======================\n") +
            _bstr_t(pXMLDoc->xml) + _bstr_t(L"\n");
    }

CleanUp:
    return bstrResult;
}

wchar_t* charToWChar(const char* text)
{
    size_t size = strlen(text) + 1;
    wchar_t* wa = new wchar_t[size];
    mbstowcs(wa, text, size);
    return wa;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: %s <xml file>\n", argv[0]);
        return 0;
    }

    HRESULT hr = CoInitialize(NULL);
    if (SUCCEEDED(hr))
    {
        try
        {
            _bstr_t bstrOutput = validateFile(charToWChar(argv[1]));
            MessageBoxW(NULL, bstrOutput, L"noNamespace", MB_OK);
        }
        catch (_com_error &e)
        {
            dump_com_error(e);
        }
        CoUninitialize();
    }

    return 0;

}
{% endhighlight %}

Notice also the following snippet:
<code>extern "C" __declspec(dllexport)  int main(int argc, char** argv);</code>

Essentially, this allows us to use <code>target_method</code> argument which DynamoRIO will try to retrieve the address for a given <a href="http://dynamorio.org/docs/group__drsyms.html#ga2e6f4d91b65fc835c047c8ca23c83d06)
">symbol name</a> as seen <a href="https://github.com/ivanfratric/winafl/blob/372a9746fb84a4c3a7656e7b79bf7e8c0c146142/winafl.c#L525">here</a>.

I could use the offsets method as per README, but due to ASLR and all that stuff, we want to scale a bit the fuzzing and spread the binary to many
Virtual Machines and use the same commands to fuzz it. The <code>extern "C"</code> directive will unmangle the function name and will make it look prettier.

To confirm that indeed DynamoRIO can use this method the following command can be used:

<code>dumpbin /EXPORTS xmlvalidate_fuzz.exe</code>

![Viewing the exported functions.]({{ site.url }}/assets/images/exported_fuctions.png)

Now let's quickly run the binary and observe the output.
You should get the following output:

![Output from the xmlvlidation binary.]({{ site.url }}/assets/images/valid_xml.png)

<h2>Code Coverage</h2>

<h3>WinAFL</h3>
Since the library is closed source, we will be using DynamoRIO's code coverage library feature via the WinAFL:

<code>C:\DRIO\bin32\drrun.exe -c winafl.dll -debug -coverage_module msxml6.dll -target_module xmlvalidate.exe -target_method main -fuzz_iterations 10 -nargs 2 --  C:\xml_fuzz_initial\xmlvalidate.exe C:\xml_fuzz_initial\nn-valid.xml</code>

WinAFL will start executing the binary ten times. Once this is done, navigate back to the winafl folder and check the log file:

![Checking the coverage within WinAFL.]({{ site.url }}/assets/images/winafl_debug_coverage.png)

From the output we can see that everything appears to be running normally! On the right side of the file, the dots depict the coverage of the DLL, if you scroll down you'll see that we did hit many function as we are getting more dots throughout the whole file. That's a very good indication that we are hiting a lot of code and we properly targeting the <b>MSXML6</b> library.

<h3>Lighthouse - Code Coverage Explorer for IDA Pro</h3>

This plugin will help us understand better which function we are hitting and give a nice overview of the coverage using IDA. It's an excellent plugin with very good documentation and has been developed by <a href="https://twitter.com/gaasedelen">Markus Gaasedelen (@gaasedelen)</a> 
Make sure to download the latest <a href="https://github.com/DynamoRIO/dynamorio/releases/download/release_7_0_0_rc1/DynamoRIO-Windows-7.0.0-RC1.zip">DynamoRIO version 7</a>, and install it as per instrcutions <a href="https://github.com/gaasedelen/lighthouse">here</a>.
Luckily, we do have two sample test cases from the documentation, one valid and one invalid. Let's feed the valid one and observe the coverage.
To do that, run the following command:

<code>C:\DRIO7\bin64\drrun.exe -t drcov -- xmlvalidate.exe nn-valid.xml</code>

Next step fire up IDA, drag the msxml6.dll and make sure to fetch the symbols!
Now, check if a .log file has been created and open it on IDA from the <b>File -> Load File -> Code Coverage File(s)</b> menu.
Once the coverage file is loaded it will highlight all the functions that your test case hit. 

<h2>Case minimisation</h2>

Now it's time to grab some XML files (as small as possible). I've used a slightly hacked version of joxean's <a href="https://raw.githubusercontent.com/joxeankoret/nightmare/master/runtime/find_samples.py">find_samples.py</a> script.
Once you get a few test cases let's minimise our initial seed files.
This can be done using the following command:

<code>python winafl-cmin.py --working-dir C:\winafl\bin32 -D C:\DRIO\bin32 -t 100000 -i C:\xml_fuzz\samples -o C:\minset_xml -coverage_module msxml6.dll -target_module xmlvalidate.exe -target_method fuzzme -nargs 1 -- C:\xml_fuzz\xmlvalidate.exe @@</code>

You might see the following output:

<code>
corpus minimization tool for WinAFL by <0vercl0k@tuxfamily.org> <br/>
Based on WinAFL by <ifratric@google.com> <br/>
Based on AFL by <lcamtuf@google.com> <br/>
[+] CWD changed to C:\winafl\bin32. <br/>
[*] Testing the target binary... <br/>
[!] Dry-run failed, 2 executions resulted differently: <br/>
  Tuples matching? False <br/>
  Return codes matching? True</code>

I am not quite sure but I think that the <b>winafl-cmin.py</b> script expects that the initial seed files
lead to the same code path, that is we have to run the script one time for the valid cases and one for the invalid ones.
I might be wrong though and maybe there's a bug which in that case I need to ping Axel.

Let's identify the 'good' and the 'bad' XML test cases using this bash script:

<code>$ for file in *; do printf "==== FILE: $file =====\n"; /cygdrive/c/xml_fuzz/xmlvalidate.exe $file ;sleep 1; done</code>

The following screenshot depicts my results:

![Looping through the test cases with Cygwin]({{ site.url }}/assets/images/cygwin_loop.png)


Feel free to expirement a bit, and see which files are causing this issue - your mileage may vary.
Once you are set, run again the above command and hopefully you'll get the following result:

![Minimising our initial seed files.]({{ site.url }}/assets/images/minimise_testcases.png)

So look at that! The initial campaign included 76 cases which after the minimisation it was narrowed down to 26. <br/>
Thank you Axel!

With the minimised test cases let's code a python script that will automate all the code coverage:

``` python
import sys
import os

testcases = []
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name.endswith(".xml"):
            testcase =  os.path.abspath(os.path.join(root, name))
            testcases.append(testcase)

for testcase in testcases:
    print "[*] Running DynamoRIO for testcase: ", testcase
    os.system("C:\\DRIO7\\bin32\\drrun.exe -t drcov -- C:\\xml_fuzz\\xmlvalidate.exe %s" % testcase)
```

The above script produced the following output for my case:

![Coverage files produced by the Lighthouse plugin.]({{ site.url }}/assets/images/lighthouse_coverage.png)

As previously, using IDA open all those .log files under <b>File -> Load File -> Code Coverage File(s)</b> menu.


![Code coverage using the Lighthouse plugin and IDA Pro.]({{ site.url }}/assets/images/msxml_code_coverage.png)

Interestingly enough, notice how many <b>parse</b> functions do exist, and if you nagivate around the coverage you'll see that 
we've managed to hit a decent amount of interesting code.

Since we do have some decent coverage, let's move on and finally fuzz it!

<h2>All I do is fuzz, fuzz, fuzz</h2>

Let's kick off the fuzzer:

<code>afl-fuzz.exe -i C:\minset_xml  -o C:\xml_results -D C:\DRIO\bin32\ -t 20000 -- -coverage_module MSXML6.dll -target_module xmlvalidate.exe -target_method main -nargs 2 -- C:\xml_fuzz\xmlvalidate.exe @@</code>

Running the above yields the following output:

![WinAFL running with a slow speed.]({{ site.url }}/assets/images/winafl_slow.png)

As you can see, the initial code does that job - however the speed is very slow.
Three executions per second will take long to give some proper results. Interestiingly enough, I've had luck in the past and with that speed (using python and <a href="https://github.com/aoh/radamsa">radamsa</a> prior the afl/winafl era) had success in finding bugs and within three days of fuzzing!

Let's try our best though and get rid of the part that slows down the fuzzing. If you've done some Windows programming you know that the following line initialises a COM object which could be the bottleneck of the slow speed:

<code><bold>HRESULT hr = CoInitialize(NULL);</bold></code>

This line probably is a major issue so in fact, let's refactor the code, we are going to create a <code>fuzzme</code> method which
is going to receive the filename as an argument outside the COM initialisation call. The refactored code should look like this:

{% highlight C %}
--- cut ---

extern "C" __declspec(dllexport) _bstr_t fuzzme(wchar_t* filename);

_bstr_t fuzzme(wchar_t* filename)
{
    _bstr_t bstrOutput = validateFile(filename);
    //bstrOutput += validateFile(L"nn-notValid.xml");
    //MessageBoxW(NULL, bstrOutput, L"noNamespace", MB_OK);
    return bstrOutput;

}
int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: %s <xml file>\n", argv[0]);
        return 0;
    }

    HRESULT hr = CoInitialize(NULL);
    if (SUCCEEDED(hr))
    {
        try
        {
            _bstr_t bstrOutput = fuzzme(charToWChar(argv[1]));
        }
        catch (_com_error &e)
        {
            dump_com_error(e);
        }
        CoUninitialize();
    }
    return 0;
}
--- cut ---
{% endhighlight %}


You can grab the refactored version <a href="{{ site.url }}/assets/files/xmlvalidate.cpp">here.</a> 
With the refactored binary let's run one more time the fuzzer and see if we were right.
This time, we will pass the <b>fuzzme</b> target_method instead of main, and use only one argument which is the filename.
While we are here, let's use the <a href="https://twitter.com/lcamtuf">lcamtuf's</a> xml.dic from <a href="https://raw.githubusercontent.com/google/oss-fuzz/master/projects/libxml2/xml.dict">here</a>.

<code>afl-fuzz.exe -i C:\minset_xml  -o C:\xml_results -D C:\DRIO\bin32\ -t 20000 -x xml.dict -- -coverage_module MSXML6.dll -target_module xmlvalidate.exe -target_method fuzzme -nargs 1 -- C:\xml_fuzz\xmlvalidate.exe @@</code>

Once you've run that, here's the output within a few seconds of fuzzing on a VMWare instance:

![WinAFL running with a massive speed.]({{ site.url }}/assets/images/winafl_fast.png)

Brilliant! That's much much better, now let it run and wait for crashes! 
<br/>

<h2>The findings - Crash triage/analysis</h2>

Generally, I've tried to fuzz this binary with different test cases, however unfortunately I kept getting the NULL pointer dereference bug. The following screenshot depicts the findings after a ~ 12 days fuzzing campaign:

![Fuzzing results after 12 days.]({{ site.url }}/assets/images/fuzzing_results.png)

Notice that a total of 33 milion executions were performed and 26 unique crashes were discovered!

In order to triage these findings, I've used the <a href="https://github.com/SkyLined/BugId">BugId</a> tool from <a hred="https://twitter.com/berendjanwever">SkyLined</a>,
it's an excellent tool which will give you a detailed report regarding the crash and the exploitability of the crash.

Here's my python code for that:

```python
import sys
import os


sys.path.append("C:\\BugId")

testcases = []
for root, dirs, files in os.walk(".\\fuzzer01\\crashes", topdown=False):
    for name in files:
        if name.endswith("00"):
            testcase =  os.path.abspath(os.path.join(root, name))
            testcases.append(testcase)

for testcase in testcases:
    print "[*] Gonna run: ", testcase
    os.system("C:\\python27\\python.exe C:\\BugId\\BugId.py C:\\Users\\IEUser\\Desktop\\xml_validate_results\\xmlvalidate.exe -- %s" % testcase)
```

The above script gives the following output:

![Running cBugId to triage the crashes..]({{ site.url }}/assets/images/crash_triage_bugid.png)

Once I ran that for all my crashes, it's clearly that we're hitting the same bug.
To confirm, let's fire up windbg: 

```
0:000> g
(a6c.5c0): Access violation - code c0000005 (!!! second chance !!!)
eax=03727aa0 ebx=0012fc3c ecx=00000000 edx=00000000 esi=030f4f1c edi=00000002
eip=6f95025a esp=0012fbcc ebp=0012fbcc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
msxml6!DTD::findEntityGeneral+0x5:
6f95025a 8b4918          mov     ecx,dword ptr [ecx+18h] ds:0023:00000018=????????
0:000> kv
ChildEBP RetAddr  Args to Child              
0012fbcc 6f9de300 03727aa0 00000002 030f4f1c msxml6!DTD::findEntityGeneral+0x5 (FPO: [Non-Fpo]) (CONV: thiscall) [d:\w7rtm\sql\xml\msxml6\xml\dtd\dtd.hxx @ 236]
0012fbe8 6f999db3 03727aa0 00000003 030c5fb0 msxml6!DTD::checkAttrEntityRef+0x14 (FPO: [Non-Fpo]) (CONV: thiscall) [d:\w7rtm\sql\xml\msxml6\xml\dtd\dtd.cxx @ 1470]
0012fc10 6f90508f 030f4f18 0012fc3c 00000000 msxml6!GetAttributeValueCollapsing+0x43 (FPO: [Non-Fpo]) (CONV: stdcall) [d:\w7rtm\sql\xml\msxml6\xml\parse\nodefactory.cxx @ 771]
0012fc28 6f902d87 00000003 030f4f14 6f9051f4 msxml6!NodeFactory::FindAttributeValue+0x3c (FPO: [Non-Fpo]) (CONV: thiscall) [d:\w7rtm\sql\xml\msxml6\xml\parse\nodefactory.cxx @ 743]
0012fc8c 6f8f7f0d 030c5fb0 030c3f20 01570040 msxml6!NodeFactory::CreateNode+0x124 (FPO: [Non-Fpo]) (CONV: stdcall) [d:\w7rtm\sql\xml\msxml6\xml\parse\nodefactory.cxx @ 444]
0012fd1c 6f8f5042 010c3f20 ffffffff c4fd70d3 msxml6!XMLParser::Run+0x740 (FPO: [Non-Fpo]) (CONV: stdcall) [d:\w7rtm\sql\xml\msxml6\xml\tokenizer\parser\xmlparser.cxx @ 1165]
0012fd58 6f8f4f93 030c3f20 c4fd7017 00000000 msxml6!Document::run+0x89 (FPO: [Non-Fpo]) (CONV: thiscall) [d:\w7rtm\sql\xml\msxml6\xml\om\document.cxx @ 1494]
0012fd9c 6f90a95b 030ddf58 00000000 00000000 msxml6!Document::_load+0x1f1 (FPO: [Non-Fpo]) (CONV: thiscall) [d:\w7rtm\sql\xml\msxml6\xml\om\document.cxx @ 1012]
0012fdc8 6f8f6c75 037278f0 00000000 c4fd73b3 msxml6!Document::load+0xa5 (FPO: [Non-Fpo]) (CONV: thiscall) [d:\w7rtm\sql\xml\msxml6\xml\om\document.cxx @ 754]
0012fe38 00401d36 00000000 00000008 00000000 msxml6!DOMDocumentWrapper::load+0x1ff (FPO: [Non-Fpo]) (CONV: stdcall) [d:\w7rtm\sql\xml\msxml6\xml\om\xmldom.cxx @ 1111]
-- cut --
```

![Running cBugId to triage the crashes..]({{ site.url }}/assets/images/windbg.png)

Let's take a look at one of the crasher:
```
C:\Users\IEUser\Desktop\xml_validate_results\fuzzer01\crashes>type id_000000_00
<?xml version="&a;1.0"?>
<book xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:noNamespaceSchemaLocation="nn.xsd"
      id="bk101">
   <author>Gambardella, Matthew</author>
   <title>XML Developer's Guide</title>
   <genre>Computer</genre>
   <price>44.95</price>
   <publish_date>2000-10-01</publish_date>
   <description>An in-depth look at creating applications with
   XML.</description>
```
As you can see, if we provide some garbage either the xml version or the encoding, we will get the above crash.
Mitja also minimised the case as seen below:

```
<?xml version='1.0' encoding='&aaa;'?>
```

The whole idea of fuzzing this library was based on finding a vulnerability within Internet Explorer's context and somehow trigger it. After a bit of googling, let's use the following PoC (<b>crashme.html</b>) and see if it will crash IE11:

```html
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<script>

var xmlDoc = new ActiveXObject("Msxml2.DOMDocument.6.0");
xmlDoc.async = false;
xmlDoc.load("crashme.xml");
if (xmlDoc.parseError.errorCode != 0) {
   var myErr = xmlDoc.parseError;
   console.log("You have error " + myErr.reason);
} else {
   console.log(xmlDoc.xml);
}

</script>
</body>
</html>
```

Running that under Python's SimpleHTTPServer gives the following:

![Running cBugId to triage the crashes..]({{ site.url }}/assets/images/ie_crash.png)

Bingo! As expected, at least with PageHeap enabled we are able to trigger exactly the same crash as with our harness.
Be careful *not* to include that xml on Microsoft Outlook, because it will also crash it as well!
Also, since it's on the library itself, had it been a more sexy crash would increase the attack surface!

<h2>Patching</h2>

After exchanging a few emails with Mitja, he kindly provided me the following patch which can be applied on a fully updated x64 system:

```
;target platform: Windows 7 x64
;
RUN_CMD C:\Users\symeon\Desktop\xmlvalidate_64bit\xmlvalidate.exe C:\Users\symeon\Desktop\xmlvalidate_64bit\poc2.xml
MODULE_PATH "C:\Windows\System32\msxml6.dll"
PATCH_ID 200000
PATCH_FORMAT_VER 2
VULN_ID 9999999
PLATFORM win64


patchlet_start
 PATCHLET_ID 1
 PATCHLET_TYPE 2
 
 PATCHLET_OFFSET 0xD093D 
 PIT msxml6.dll!0xD097D
  
 code_start

  test rbp, rbp ;is rbp (this) NULL?
  jnz continue
  jmp PIT_0xD097D
  continue:
 code_end
patchlet_end
```

Let's debug and test that patch, I've created an account and installed the 0patch agent for developers, and continued by right clicking on the above <code>.0pp</code> file:

![Running the crasher with the 0patch console]({{ site.url }}/assets/images/0patch_debug.png)

Once I've executed my harness with the xml crasher, I immediately hit the breakpoint:

![Hitting the breakpoint under Windbg]({{ site.url }}/assets/images/0patch_breakpoint.png)

From the code above, indeed <b>rbp</b> is <code>null</code> which would lead to the null pointer dereference.
Since we have deployed the 0patch agent though, in fact it's going to jump to <code>msxml6.dll!0xD097D</code> and avoid the crash:

![Bug fully patched!]({{ site.url }}/assets/images/msxml_patched.png)

Fantastic! My next step was to fire up winafl again with the patched version which unfortunately failed.
Due to the nature of 0patch (function hooking?) it does not play nice with WinAFL and it crashes it.

Nevertheless, this is a sort of "DoS 0day" and as I mentioned earlier I reported it to Microsoft back in June 2017 and after twenty days I got the following email:

![MSRC Response!]({{ site.url }}/assets/images/msrc_response.png)

I totally agree with that decision, however I was mostly interested in patching the annoying bug so I can move on with my fuzzing :o) <br/>
After spending a few hours on the debugger, the only "controllable" user input would be the length of the encoding string:

```
eax=03052660 ebx=0012fc3c ecx=00000011 edx=00000020 esi=03054f24 edi=00000002
eip=6f80e616 esp=0012fbd4 ebp=0012fbe4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
msxml6!Name::create+0xf:
6f80e616 e8e7e6f9ff      call    msxml6!Name::create (6f7acd02)
0:000> dds esp L3
0012fbd4  00000000
0012fbd8  03064ff8
0012fbdc  00000003

0:000> dc 03064ff8 L4
03064ff8  00610061 00000061 ???????? ????????  a.a.a...????????
```

The above unicode string is in fact our entiny from the test case, where the number 3 is the length aparently 
(and the signature of the fuction: <code>Name *__stdcall Name::create(String *pS, const wchar_t *pch, int iLen, Atom *pAtomURN))</code>

<h2>Conclusion</h2>

First of all, I can' thank enough Ivan for porting the afl to Windows and creating this amazing project.
Moreover thanks to Axel as well who's been actively contributing and adding amazing features.

Shouts to my colleague <a href="https://twitter.com/NeomindMusic">Javier</a> (we all have one of those heap junkie friends, right?) for motivating me to write this blog, <a href="https://twitter.com/richinseattle">Richard</a> who's been answering my silly questions and helping me all this time, Mitja from the 0patch team for building this patch and finally <a href="https://twitter.com/_argp">Patroklo</a> for teaching me a few tricks about fuzzing a few years ago!

<h2>References</h2>
<a href="https://github.com/richinseattle/EvolutionaryKernelFuzzing/blob/master/slides/Evolutionary%20Kernel%20Fuzzing-BH2017-rjohnson-FINAL.pdf">Evolutionary Kernel Fuzzing-BH2017-rjohnson-FINAL.pdf</a><br/>
<a href="https://labsblog.f-secure.com/2017/06/22/super-awesome-fuzzing-part-one/">Super Awesome Fuzzing, Part One</a>
