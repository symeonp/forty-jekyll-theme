---
layout: post
title: Grammar based fuzzing PDFs with Domato
description: Using domato to fuzz PDF parsers
image: assets/images/domato-grammar.png
---


<h2>Introduction</h2>

Welcome back to another fuzzing blog post. This time let's talk about grammar based fuzzing!
I will be writing how I tried to fuzz a few PDF software such as Foxit and Adobe.

In order to do that, I used the following tools:

- <a href="https://github.com/googleprojectzero/domato">domato</a>, grab it from its repo while it's fresh!

- <a href="https://www.debenu.com/products/development/debenu-pdf-library/">Debenu Quick PDF Library</a>, for my campaign the current version as of this writing is 17.11 but YMMV, please note that you need to register in order to request a trial.

- <a href="https://github.com/SkyLined/BugId">BugId</a> to help us triage any crashes/save crashers.

- Your favourite PDF parser/software!

So here's the idea: We will be installing the Debenu Quick PDF library and take advantage of its SDK and functions.
Why grammar based on a massive complex format such as a PDF you say? Remember that the PDF file format includes
texts, images, multimedia, JavaScript and has very complex parsing code. As such, although a smart guided fuzzer can be used
such as <a href="https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/"> Checkpoint's research</a>, we can take advantage of this library which provides a tons of features from messing with HTML objects to adding images, fonts, or even adding
custom javascript!


<h2>Grammar Based Fuzzing</h2>

From the wiki: A smart (model-based, grammar-based,or protocol-based fuzzer leverages the input model to generate a greater proportion of valid inputs. For instance, if the input can be modelled as an abstract syntax tree, then a smart mutation-based fuzzer would employ random transformations to move complete subtrees from one node to another. If the input can be modelled by a formal grammar, a smart generation-based fuzzer would instantiate the production rules to generate inputs that are valid with respect to the grammar. However, generally the input model must be explicitly provided, which is difficult to do when the model is proprietary, unknown, or very complex.

In short, grammar based is aware of input structure, and instead of dumb fuzzing where we simply mutate bytes without having any knowledge of the target/file/network protocol specification we do have knowledge of the structure (such as the API presented here) and we will be generating test cased based on that specification.

There are many tutorials out there, but I recommend having a look at domato's page, where you can fully understand how it works.
As mentioned earlier, we will be creating a grammar so the function

<code>int DPLDrawHTMLText(int InstanceID, double Left, double Top, double Width, wchar_t * HTMLText)</code>

can be called with bogus; yet <b>valid</b> input such as the following:

{% highlight C %}
DrawHTMLText(1,2,1,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
DrawHTMLText(0.285839975231,4.0,10000000.0,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
DrawHTMLText(5.0,4294967295.0,2147483647.0,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
DrawHTMLText(65.862385207,9.2399248386,8.01963632388,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
{% endhighlight %}


<h2>Getting started with Debenu Quick PDF Library</h2>

Once you obtain your trial and install it, you need to register the ActiveX DLL.
This can be done by either running <code>%systemroot%\System32\regsvr32.exe</code> targeting the 64-bit version of the DLL
(<b>DebenuPDFLibrary64AX1711.dll</b>) or <code>%systemroot%\SysWoW64\regsvr32.exe</code> to register the 32-bit version (<b>DebenuPDFLibraryAX1711.dll</b>)
While you are there make sure to note down the <b>TRIAL_LICENSE_KEY.TXT</b> as you'll need it later for generated the files.

![Registering the DLL.]({{ site.url }}/assets/images/dll_register.png)


Exploring the library and reading the documenation we can see that the library offers a variety of bindings:
From C#, C++, Delphi, Objective-C to Perl, PHP, VB6, VBScript and Visual Basic (.NET). If you want to experiment,
go ahead and check <a href="https://www.debenu.com/products/development/debenu-pdf-library/help/samples/">this</a> page!
The library moreover, provides many function groups that can be targeted:

<img src="{{site.url}}/assets/images/function_groups.png" width="800" height="800">


For my case, I ended up using the Visual Basic and Perl bindings. Once you create a grammar it's very easy to modify
the template and use another language, and that's they beauty of grammar based fuzzing!

Let's use this following Visual Basic example:


{% highlight VisualBasic %}
' Debenu Quick PDF Library Sample

' * Remember to set your license key below
' * This sample shows how to unlock the library, draw some
'   simple text onto the page and save the PDF
' * A file called hello-world.pdf is written to disk

WScript.Echo("Hello World - Debenu Quick PDF Library Sample")

Dim ClassName
Dim LicenseKey
Dim FileName

ClassName = "DebenuPDFLibraryAX1711.PDFLibrary"
LicenseKey = "" ' INSERT LICENSE KEY HERE
FileName = "hello-world.pdf"

Dim DPL
Dim Result

Set DPL = CreateObject(ClassName)
WScript.Echo("Library version: " + DPL.LibraryVersion)
Result = DPL.UnlockKey(LicenseKey)
If Result = 1 Then
  WScript.Echo("Valid license key: " + DPL.LicenseInfo)
  Call DPL.DrawText(100, 500, "Hello world from VBScript")
  If DPL.SaveToFile(FileName) = 1 Then
    WScript.Echo("File " + FileName + " written successfully")
  Else
    WScript.Echo("Error, file could not be written")
  End If
Else
  WScript.Echo("- Invalid license key -")
  WScript.Echo("Please set your license key by editing this file")
End If

Set DPL = Nothing
{% endhighlight %}

Executing it with the 32-bit version of the DLL yields the following output:

![Generating the PDF from Visual Basic.]({{ site.url }}/assets/images/generate_hello_world.png)

Opening it with Foxit we can confirm that our file has been generated!

![Generating the PDF from Visual Basic.]({{ site.url }}/assets/images/hello-world-pdf.png)

Success! Within few minutes, we managed to set up the library, get some sample code and generate a valid PDF.
Let's move on!


<h2>Creating the grammar</h2>


To demonstrate domato's capabilities, let's target the following <a href="https://www.debenu.com/docs/pdf_library_reference/DrawHTMLText.php">sample function:</a>

<img src="{{site.url}}/assets/images/drawhtml.png" width="800" height="600">


As you can see, this function expects four parameters: <code>double Left, double Top, double Width,
  wchar_t * HTMLText)</code>

As such, the SDK expects the following call:

<code>DrawHTML(200.0, 400.0, 800.0,"my text")</code>

Forming the above function call with domato and creating a grammar is straightforward, we simply need to define a symbol and assign its corresponding value.
The value can be something like <code>MAX_INT</code> or <code>MIN_INT</code> interesting values, common values that they may lead to common signed/unsigned integer overflows/underflows or undefined behaviour.

{% highlight Perl %}

<fuzzstring> = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

<interestingint> = 32768
<interestingint> = 65535
<interestingint> = 65536
<interestingint> = 1073741824
<interestingint> = 536870912
<interestingint> = 268435456
<interestingint> = 4294967295
<interestingint> = 2147483648
<interestingint> = 2147483647
<interestingint> = -2147483648
<interestingint> = -1073741824
<interestingint> = -32769

<fuzzdouble> = -1.0
<fuzzdouble> = 0.0
<fuzzdouble> = 1.0
<fuzzdouble> = 2.0
<fuzzdouble> = 3.0
<fuzzdouble> = 4.0
<fuzzdouble> = 5.0
<fuzzdouble> = 10.0
<fuzzdouble> = 1000.0
<fuzzdouble> = 10000.0
<fuzzdouble> = 10000000.0
<fuzzdouble> = <double min=0 max=10>
<fuzzdouble> = <double min=0 max=100>
<fuzzdouble> = <largedouble>
<fuzzdouble> = <interestingint>

<LeftTopWidth> = <fuzzdouble>,<fuzzdouble>,<fuzzdouble>


<HTMLText> = DrawHTMLText(<LeftTopWidth>,<fuzzstring>)

{% endhighlight %}

Continuing, since we will be generating programming language code we have to include the <code>!begin lines</code> and <code>!end lines</code> keywords:


{% highlight PHP %}
!begin lines

$QP-><HTMLText>;

!end lines
{% endhighlight %}

Following the API specification and creating the <b><code>HTMLText</code></b> method can be formed within literally a few lines:

![Generating grammar for the HTMLText.]({{ site.url }}/assets/images/htmltext-grammar.png)


<h3>Creating the template.pl</h3>


Once you have the basic grammar, how are we going to call these function within our binding?
In fact, looking at previous <a href="https://github.com/googleprojectzero/domato/blob/master/canvas/template.html">github code</a>, we
simply need to provide the sample code we were given with slightly modifications as seen below:

![Template for the Perl bindings.]({{ site.url }}/assets/images/template.png)


From the screenshot above, you can see that the code within the <b>&lt;DPLFuzz&gt;</b> will get substituted with the 
<code>$QP->&lt;HTMLText&gt;</code> generated cases! Here's a sample how it looks like once domato has done its magic:


![Generated test cases.]({{ site.url }}/assets/images/generated_cases_drawhtml.png)


Now our next step is to create a file where it actually generates this grammar (called a <b>generator</b>). This can be achieved by using the already existing ones, 
such as <a href="https://github.com/googleprojectzero/domato/blob/master/canvas/generator.py">Ivan's generator.py</a>, with a few modifications:

{% highlight Python %}
#   Domato - main generator script
#   -------------------------------
#
#   Written and maintained by Ivan Fratric <ifratric@google.com>
#
#   Copyright 2017 Google Inc. All Rights Reserved.
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from __future__ import print_function
import os
import re
import random
import sys

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.append(parent_dir)
from grammar import Grammar

_N_MAIN_LINES = 50
_N_EVENTHANDLER_LINES = 25

def generate_function_body(jsgrammar, num_lines):
    js = jsgrammar._generate_code(num_lines)
    return js

def GenerateNewSample(template, jsgrammar):
    """Parses grammar rules from string.
    Args:
      template: A template string.
      htmlgrammar: Grammar for generating HTML code.
      cssgrammar: Grammar for generating CSS code.
      jsgrammar: Grammar for generating JS code.
    Returns:
      A string containing sample data.
    """

    result = template

    handlers = False
    while '<DPLFuzz>' in result:
        numlines = _N_MAIN_LINES
        if handlers:
            numlines = _N_EVENTHANDLER_LINES
        else:
            handlers = True
        result = result.replace(
            '<DPLFuzz>',
            generate_function_body(jsgrammar, numlines),
            1
        )

    return result


def generate_samples(grammar_dir, outfiles):
    """Generates a set of samples and writes them to the output files.
    Args:
      grammar_dir: directory to load grammar files from.
      outfiles: A list of output filenames.
    """

    f = open(os.path.join(grammar_dir, 'template.pl'))
    template = f.read()
    f.close()

    jsgrammar = Grammar()
    err = jsgrammar.parse_from_file(os.path.join(grammar_dir, 'DPL.txt'))
    if err > 0:
        print('There were errors parsing grammar')
        return

    for outfile in outfiles:
        result = GenerateNewSample(template, jsgrammar)

        if result is not None:
            print('Writing a sample to ' + outfile)
            try:
                f = open(outfile, 'w')
                f.write(result)
                f.close()
            except IOError:
                print('Error writing to output')


def get_option(option_name):
    for i in range(len(sys.argv)):
        if (sys.argv[i] == option_name) and ((i + 1) < len(sys.argv)):
            return sys.argv[i + 1]
        elif sys.argv[i].startswith(option_name + '='):
            return sys.argv[i][len(option_name) + 1:]
    return None


def main():
    fuzzer_dir = os.path.dirname(__file__)

    multiple_samples = False

    for a in sys.argv:
        if a.startswith('--output_dir='):
            multiple_samples = True
    if '--output_dir' in sys.argv:
        multiple_samples = True

    if multiple_samples:
        print('Running on ClusterFuzz')
        out_dir = get_option('--output_dir')
        nsamples = int(get_option('--no_of_files'))
        print('Output directory: ' + out_dir)
        print('Number of samples: ' + str(nsamples))

        if not os.path.exists(out_dir):
            os.mkdir(out_dir)

        outfiles = []
        for i in range(nsamples):
            outfiles.append(os.path.join(out_dir, 'fuzz-' + str(i).zfill(5) + '.pl'))

        generate_samples(fuzzer_dir, outfiles)

    elif len(sys.argv) > 1:
        outfile = sys.argv[1]
        generate_samples(fuzzer_dir, [outfile])

    else:
        print('Arguments missing')
        print("Usage:")
        print("\tpython generator.py <output file>")
        print("\tpython generator.py --output_dir <output directory> --no_of_files <number of output files>")

if __name__ == '__main__':
    main()
{% endhighlight %}

<h3>Saving the actual test cases</h3>

Before we continue, notice how on the provided sample code <b>(hello-world.vbs)</b> this line was responsible to for saving the file name:
<code>FileName = "hello-world.pdf"</code>. This one is hardcoded, and certianly does not suit us. 
In order to solve this issue, I've coded something very simple, a python script which finds the "placeholder" which
is the hardcoded value <b>XXX</b>, and replaces it with <code>filename-&lt;num&gt;.pdf</code>:


![Replacing the actual filename.]({{ site.url }}/assets/images/replace.png)


<h2>BugId and you!</h2>

If you haven't read already the <a href="https://blog.skylined.nl/20181017001.html">Fuzz in sixty seconds article</a> blog, please
spend some time and see how BugId can be integrated into your fuzzing workflow. The idea is very similar, but instead of fuzzing browsers, we are looping through the generated cases one by one; I have modified some parts to reflect those changes as seen below:

![Replacing the actual filename.]({{ site.url }}/assets/images/bugId.png)


Essentially, here we are executing Domato's generator, replacing the <b>XXX</b> marker with the actual filename, executing
the perl generated cases from domato, and finally save the generated PDFs to our test folder.


With the above modifications, once the <b>BAT</b> file is executed, it gives us the following screenshot:


![Executing the generator.]({{ site.url }}/assets/images/command_line.png)


<h2>Putting it all together</h2>

With all these steps combined, let's run the cmd file, and see how this goes:

![Fuzzint it.]({{ site.url }}/assets/images/pdf_fuzz.png)

Et voila! By using open source tools, and with some effort we are able now to fuzz not only Foxit software, but pretty
much any PDF parser out there!


<h3>The results</h3>

Surprisingly, although I did a lot of effort from creating the grammar to modifying BugId, unfortunately the only crashes I managed to get were some meaningless NULL pointer dereferences. You'd expect that such software has been fuzzed to death, however as j00ru once
said <a href="https://twitter.com/j00ru/status/1163766807494365190?s=20">according to the bug hunter's law... there is always one more bug :)</a>


<h2>Caveats</h2>

Interestingly enough, I initially used the Visual Basic bindings. However, once a very large integer was passed to these methods,
Visual Basic would complain and fail to generate the case as seen below:

![Visual Basic issues.]({{ site.url }}/assets/images/vb-issues.png)

Please note how it also informs the user in case the parameters or the assignments are wrong, that's very handy and can be used for your advantage!

<h2>Conclusion</h2>

In this blog post we've covered a very brief introduction to grammar based fuzzing. We have used the Quick PDF library where we could
apply this knowledge and demonstrated how we can create a grammar from scratch and fuzz a sample function within the API generating structure aware test cases. Finally, we've used BugId to iterate over our cases in case any crashes were found. The sky is the limit, this type of fuzzing can be used not only for this specific library, but for every file format which is text based or even programming languages! 

I hope you enjoyed as much as I did! As always, any ideas, comments, feedback is welcome!
