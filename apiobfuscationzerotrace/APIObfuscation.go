package main

import (
	"encoding/hex"
	"fmt"
)


func obfuscate(input string) string {
	key := byte(0x41) // 'A'
	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i] ^ key
	}
	return hex.EncodeToString(result)
}


func deobfuscate(hexStr string) string {
	key := byte(0x41) // 'A'
	decoded, _ := hex.DecodeString(hexStr)
	result := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i++ {
		result[i] = decoded[i] ^ key
	}
	return string(result)
}

func main() {

	ntdllStr := "ntdll.dll"
	kernel32Str := "kernel32.dll"


	funcNames := []string{
		"NtResumeThread",
		"VirtualAllocEx",
		"NtGetContextThread",
		"NtSetContextThread",
		"NtReadVirtualMemory",
		"NtUnmapViewOfSection",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"InitializeProcThreadAttributeList",
		"UpdateProcThreadAttribute",
		"DeleteProcThreadAttributeList",
		"GetProcessHeap",
		"HeapAlloc",
		"HeapFree",
	}


	ntdllHex := obfuscate(ntdllStr)
	kernel32Hex := obfuscate(kernel32Str)

	fmt.Println("=== Obfuscated DLL Names ===")
	fmt.Printf("ntdll.dll: %s\n", ntdllHex)
	fmt.Printf("kernel32.dll: %s\n", kernel32Hex)

	
	fmt.Println("\n=== Obfuscated Function Names ===")
	funcHexes := make([]string, len(funcNames))
	for i, name := range funcNames {
		funcHexes[i] = obfuscate(name)
		fmt.Printf("%s: %s\n", name, funcHexes[i])
	}

	
	fmt.Println("\n=== Generated Code for Deobfuscation ===")

	fmt.Println(`import (
    "encoding/hex"
    "syscall"
)


func deobfuscate(hexStr string) string {
    key := byte(0x41) // 'A'
    decoded, _ := hex.DecodeString(hexStr)
    result := make([]byte, len(decoded))
    for i := 0; i < len(decoded); i++ {
        result[i] = decoded[i] ^ key
    }
    return string(result)
}

var (`)

	fmt.Printf("\tntdllHex = \"%s\"\n", ntdllHex)
	fmt.Printf("\tkernel32Hex = \"%s\"\n\n", kernel32Hex)

	for i, name := range funcNames {
		fmt.Printf("\t%sHex = \"%s\"\n", name, funcHexes[i])
	}

	fmt.Println(`
 
    ntdll    = syscall.NewLazyDLL(deobfuscate(ntdllHex))
    kernel32 = syscall.NewLazyDLL(deobfuscate(kernel32Hex))
    
   

	fmt.Printf("\tpNtResumeThread = ntdll.NewProc(deobfuscate(NtResumeThreadHex))\n")
	fmt.Printf("\tpVirtualAllocEx = kernel32.NewProc(deobfuscate(VirtualAllocExHex))\n")
	fmt.Printf("\tpNtGetContextThread = ntdll.NewProc(deobfuscate(NtGetContextThreadHex))\n")
	fmt.Printf("\tpNtSetContextThread = ntdll.NewProc(deobfuscate(NtSetContextThreadHex))\n")
	fmt.Printf("\tpNtReadVirtualMemory = ntdll.NewProc(deobfuscate(NtReadVirtualMemoryHex))\n")
	fmt.Printf("\tpNtUnmapViewOfSection = ntdll.NewProc(deobfuscate(NtUnmapViewOfSectionHex))\n")
	fmt.Printf("\tpNtWriteVirtualMemory = ntdll.NewProc(deobfuscate(NtWriteVirtualMemoryHex))\n")
	fmt.Printf("\tpNtProtectVirtualMemory = ntdll.NewProc(deobfuscate(NtProtectVirtualMemoryHex))\n")

	fmt.Println(`
  

	fmt.Printf("\tprocInitializeProcThreadAttributeList = kernel32.NewProc(deobfuscate(InitializeProcThreadAttributeListHex))\n")
	fmt.Printf("\tprocUpdateProcThreadAttribute = kernel32.NewProc(deobfuscate(UpdateProcThreadAttributeHex))\n")
	fmt.Printf("\tprocDeleteProcThreadAttributeList = kernel32.NewProc(deobfuscate(DeleteProcThreadAttributeListHex))\n")
	fmt.Printf("\tprocGetProcessHeap = kernel32.NewProc(deobfuscate(GetProcessHeapHex))\n")
	fmt.Printf("\tprocHeapAlloc = kernel32.NewProc(deobfuscate(HeapAllocHex))\n")
	fmt.Printf("\tprocHeapFree = kernel32.NewProc(deobfuscate(HeapFreeHex))\n")

	fmt.Println(")")
}
