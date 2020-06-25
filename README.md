                                               
# GoGhost

GoGhost is a High Performance, lightweight, portable Open Source tool for mass SMBGhost Scan.

![GoGhost Running](https://github.com/deepsecurity-pe/GoGhost/blob/master/GoGhost.PNG)


## Installation

You can download [Windows Binary](https://github.com/deepsecurity-pe/GoGhost/blob/master/GoGhost_win_amd64.exe) or [Linux Binary](https://github.com/deepsecurity-pe/GoGhost/blob/master/GoGhost_linux_amd64). Alternatively, GoGhost uses native Golang libraries so the line above would be fine to compile it:

```
go build GoGhost.go
```    

## Usage Options
<img src="https://github.com/deepsecurity-pe/GoGhost/blob/master/GoGhostGif.gif" width="690" />

GoGhost Scanned 25,000 IP addresses in less than 3 seconds, NMAP took more than 600.

![NMAP vs GoGhost](https://github.com/deepsecurity-pe/GoGhost/blob/master/NMAP_vs_GoGhost.jpg)

#### `-iL [FILE]`
By using the -iL option you're able to specify a list file with CIDRs in file.

#### `-iR [CIDR]`
By using the -iR option you're able to specify an IP Range.

## False Positive & False Negative
If the Windows is patched with KB4551762, GoGhost will still flag it as vulnerable. If the list of CIDRs in the file is bigger than 500k IP Addresses it may flag some vulnerable as Timeout. 

## The Results
Timeout => Closed Port

Not Vulnerable => Does not has compression

Vulnerable => LZNT1 compression on SMB.

## Disclaimer
This tool was coded to measure the impact of SMBGhost in [Latin America](https://deepsecurity.pe/blog) and Deepsecurity is not responsible for the use of this tool. 
