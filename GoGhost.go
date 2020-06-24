package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"flag"
)

const (
	pkt =
	"\x00" + // session
	"\x00\x00\xc0"+ // legth

	"\xfeSMB@\x00"+ // protocol

	//[MS-SMB2]: SMB2 NEGOTIATE Request 
	//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5

	"\x00\x00" +
	"\x00\x00" +
	"\x00\x00" +
	"\x00\x00" +
	"\x1f\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" + 

	// [MS-SMB2]: SMB2 NEGOTIATE_CONTEXT
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7

	"$\x00" +
	"\x08\x00" +
	"\x01\x00" +
	"\x00\x00" +
	"\x7f\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"x\x00" +
	"\x00\x00" +
	"\x02\x00" +
	"\x00\x00" +
	"\x02\x02" +
	"\x10\x02" +
	"\x22\x02" +
	"$\x02" +
	"\x00\x03" +
	"\x02\x03" +
	"\x10\x03" +
	"\x11\x03" +
	"\x00\x00\x00\x00" +


	// [MS-SMB2]: SMB2_PREAUTH_INTEGRITY_CAPABILITIES
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5

	"\x01\x00" +
	"&\x00" +
	"\x00\x00\x00\x00" +
	"\x01\x00" +
	"\x20\x00" +
	"\x01\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00\x00\x00" +
	"\x00\x00" +

	// [MS-SMB2]: SMB2_COMPRESSION_CAPABILITIES
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271

	"\x03\x00" +
	"\x0e\x00" +
	"\x00\x00\x00\x00" +
	"\x01\x00" + //CompressionAlgorithmCount
	"\x00\x00" +
	"\x01\x00\x00\x00" +
	"\x01\x00" + //LZNT1
	"\x00\x00" +
	"\x00\x00\x00\x00"
)

var wg sync.WaitGroup

func socketX(ip string, port int) {
	defer wg.Done()
	addr := strings.Join([]string{ip, strconv.Itoa(port)}, ":")
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)

	if err != nil {
		fmt.Println(ip + " Timeout")
	} else {

		defer conn.Close()

		conn.Write([]byte(pkt))

		buff := make([]byte, 1024)
		err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buff)
		if err != nil {
			fmt.Println(err.Error()) // Profound analysis
		}

		if bytes.Contains([]byte(buff[:n]), []byte("Public")) == true {
			fmt.Println(ip + " Compression Enabled - Vulnerable")

		} else {
			fmt.Println(ip + " Not Vulnerable")
		}
	}
}

	///////////////////////////////
	//							 //
	//			Parse IP 		 // 				
	//						   	 //
	//////////////////////////////
func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println(err.Error())
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	
	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil
	
	default:
	return ips[1 : len(ips)-1], nil
	}
}


func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}



func main() {

	ilPtr := flag.String("iL", "", "List of IP Addresses on File.")
	irPtr := flag.String("iR", "", "IP Range Ex. 192.169.1.0/24")

	flag.Parse()





	///////////////////////////////
	//							 //
	//			List Scan 		 // 				
	//						   	 //
	///////////////////////////////
	if *ilPtr != "" {

	readFile, err := os.Open(*ilPtr)

	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileTextLines []string

	for fileScanner.Scan() {
		fileTextLines = append(fileTextLines, fileScanner.Text())
	}

	readFile.Close()



	fmt.Println("==== START TIME ==== ")
	fmt.Println(time.Now())

	for _, eachline := range fileTextLines {
		ReadIP, err := Hosts(eachline)
		if err != nil {
			log.Fatal(err)
		}
		iplen := len(ReadIP)
		wg.Add(iplen)

		for _, eachip := range ReadIP {
			go socketX(eachip, 445)
		}

	}
	wg.Wait()
	fmt.Println("==== END TIME ==== ")
	fmt.Println(time.Now())


	///////////////////////////////
	//							 //
	//			IP Scan 		 // 				
	//						   	 //
	//////////////////////////////
	}else if *irPtr != ""{


	ReadIP, err := Hosts(*irPtr)
	if err != nil {
		log.Fatal(err)
	}

	iplen := len(ReadIP)

	wg.Add(iplen)

	fmt.Println("==== START TIME ==== ")
	fmt.Println(time.Now())
	for _, eachline := range ReadIP {
		go socketX(eachline, 445)
	}
	wg.Wait()
	fmt.Println("==== END TIME ==== ")
	fmt.Println(time.Now())



	///////////////////////////////
	//							 //
	//		Banner - Help 		 // 				
	//						   	 //
	//////////////////////////////




	}else{
		fmt.Println("\033[92m\033[1m")
		
		fmt.Println("  ________         ________.__                    __   ");
		fmt.Println(" /  _____/  ____  /  _____/|  |__   ____  _______/  |_ ");
		fmt.Println("/   \\  ___ /  _ \\/   \\  ___|  |  \\ /  _ \\/  ___/\\   __\\");
		fmt.Println("\\    \\_\\  (  <_> )    \\_\\  \\   Y  (  <_> )___ \\  |  |  ");
		fmt.Println(" \\______  /\\____/ \\______  /___|  /\\____/____  > |__|  ");
		fmt.Println("        \\/               \\/     \\/           \\/        ");
		fmt.Println("                                                       ");
		fmt.Println("                                             By @DeepSecurity_.          ");
		
		fmt.Println("\033[0m")

		flag.PrintDefaults()
	}
}
