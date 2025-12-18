//! RISC-V ELF binary loader.
//!
//! Parses ELF32 binaries (RISC-V RV32IM) and loads them into memory for execution.
//! Supports both executable (ET_EXEC) and shared object (ET_DYN) files.
//!
//! # ELF Format Overview
//!
//! An ELF file consists of:
//! - ELF header (52 bytes for 32-bit): Contains magic number, machine type, entry point
//! - Program headers: Describe loadable segments (PT_LOAD)
//! - Section headers: Describe sections (.text, .data, .bss, etc.)
//! - Segment/section data
//!
//! # Usage
//!
//! ```ignore
//! use zp1_executor::elf::ElfLoader;
//! use zp1_executor::memory::Memory;
//!
//! let elf_data = std::fs::read("program.elf")?;
//! let loader = ElfLoader::parse(&elf_data)?;
//! let mut memory = Memory::with_default_size();
//! let entry_point = loader.load_into_memory(&mut memory)?;
//! ```

use crate::error::ExecutorError;
use crate::memory::Memory;

// ============================================================================
// ELF Constants
// ============================================================================

/// ELF magic number: 0x7f 'E' 'L' 'F'
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class: 32-bit
const ELFCLASS32: u8 = 1;

/// ELF data encoding: little-endian (LSB first)
const ELFDATA2LSB: u8 = 1;

/// Current ELF version
const EV_CURRENT: u8 = 1;

/// ELF type: Executable file
const ET_EXEC: u16 = 2;

/// ELF type: Shared object file (position-independent executable)
const ET_DYN: u16 = 3;

/// ELF machine type: RISC-V
const EM_RISCV: u16 = 243;

/// Program header type: Null (ignored)
const _PT_NULL: u32 = 0;

/// Program header type: Loadable segment
const PT_LOAD: u32 = 1;

/// Program header type: Dynamic linking info
const _PT_DYNAMIC: u32 = 2;

/// Program header type: Interpreter path
const _PT_INTERP: u32 = 3;

/// Program header type: Note section
const _PT_NOTE: u32 = 4;

/// Program header type: Program header table
const _PT_PHDR: u32 = 6;

/// Program header type: Thread-local storage template
const _PT_TLS: u32 = 7;

/// Section type: Null (inactive)
const _SHT_NULL: u32 = 0;

/// Section type: Program data
const _SHT_PROGBITS: u32 = 1;

/// Section type: Symbol table
const SHT_SYMTAB: u32 = 2;

/// Section type: String table
const SHT_STRTAB: u32 = 3;

/// Section type: Relocation with addend
const _SHT_RELA: u32 = 4;

/// Section type: No bits (BSS)
const _SHT_NOBITS: u32 = 8;

/// Section type: Relocation without addend
const _SHT_REL: u32 = 9;

/// Section type: Dynamic symbol table
const SHT_DYNSYM: u32 = 11;

/// ELF header size for 32-bit
const ELF32_HEADER_SIZE: usize = 52;

/// Program header size for 32-bit
const ELF32_PHDR_SIZE: usize = 32;

/// Section header size for 32-bit
const ELF32_SHDR_SIZE: usize = 40;

/// Symbol table entry size for 32-bit
const ELF32_SYM_SIZE: usize = 16;

// ============================================================================
// ELF Structures
// ============================================================================

/// ELF file header (32-bit).
///
/// The ELF header is always at the beginning of the file and contains
/// essential information about the file format and where to find other
/// structures.
#[derive(Debug, Clone)]
pub struct Elf32Header {
    /// ELF type (ET_EXEC, ET_DYN, etc.)
    pub e_type: u16,
    /// Target machine architecture
    pub e_machine: u16,
    /// ELF version (should be 1)
    pub e_version: u32,
    /// Entry point virtual address
    pub entry: u32,
    /// Program header table file offset
    pub phoff: u32,
    /// Section header table file offset
    pub shoff: u32,
    /// Processor-specific flags
    pub flags: u32,
    /// ELF header size in bytes
    pub ehsize: u16,
    /// Program header table entry size
    pub phentsize: u16,
    /// Number of program header entries
    pub phnum: u16,
    /// Section header table entry size
    pub shentsize: u16,
    /// Number of section header entries
    pub shnum: u16,
    /// Section name string table index
    pub shstrndx: u16,
}

/// Program header (32-bit).
///
/// Program headers describe segments used for program loading.
/// The most important type is PT_LOAD, which describes memory regions
/// that need to be loaded from the file.
#[derive(Debug, Clone)]
pub struct Elf32ProgramHeader {
    /// Segment type (PT_LOAD, PT_DYNAMIC, etc.)
    pub p_type: u32,
    /// Offset of segment data in file
    pub p_offset: u32,
    /// Virtual address in memory
    pub p_vaddr: u32,
    /// Physical address (usually same as vaddr)
    pub p_paddr: u32,
    /// Size of segment data in file
    pub p_filesz: u32,
    /// Size of segment in memory (may be larger for BSS)
    pub p_memsz: u32,
    /// Segment flags (PF_R, PF_W, PF_X)
    pub p_flags: u32,
    /// Alignment requirement (power of 2)
    pub p_align: u32,
}

/// Section header (32-bit).
///
/// Section headers describe the logical structure of the ELF file,
/// including code (.text), data (.data), uninitialized data (.bss),
/// symbol tables, and string tables.
#[derive(Debug, Clone)]
pub struct Elf32SectionHeader {
    /// Section name (offset into string table)
    pub sh_name: u32,
    /// Section type (SHT_PROGBITS, SHT_NOBITS, etc.)
    pub sh_type: u32,
    /// Section flags (SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR)
    pub sh_flags: u32,
    /// Virtual address if section is allocated
    pub sh_addr: u32,
    /// Offset in file
    pub sh_offset: u32,
    /// Size in bytes
    pub sh_size: u32,
    /// Link to another section
    pub sh_link: u32,
    /// Additional section info
    pub sh_info: u32,
    /// Alignment requirement
    pub sh_addralign: u32,
    /// Entry size if section holds table
    pub sh_entsize: u32,
}

/// Symbol table entry (32-bit).
#[derive(Debug, Clone)]
pub struct Elf32Symbol {
    /// Symbol name (offset into string table)
    pub st_name: u32,
    /// Symbol value (address)
    pub st_value: u32,
    /// Symbol size
    pub st_size: u32,
    /// Symbol type and binding
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: u16,
}

impl Elf32Symbol {
    /// Get symbol binding (local, global, weak)
    pub fn binding(&self) -> u8 {
        self.st_info >> 4
    }

    /// Get symbol type (notype, object, func, section, file)
    pub fn symbol_type(&self) -> u8 {
        self.st_info & 0xf
    }

    /// Check if symbol is a function
    pub fn is_function(&self) -> bool {
        self.symbol_type() == 2 // STT_FUNC
    }

    /// Check if symbol is global
    pub fn is_global(&self) -> bool {
        self.binding() == 1 // STB_GLOBAL
    }
}

// ============================================================================
// ELF Loader
// ============================================================================

/// ELF loader for RISC-V 32-bit binaries.
///
/// Parses ELF files and loads them into memory for execution.
/// Supports standard executable and position-independent executables.
#[derive(Debug)]
pub struct ElfLoader {
    /// Raw ELF file data
    data: Vec<u8>,
    /// Parsed ELF header
    header: Elf32Header,
    /// Parsed program headers
    program_headers: Vec<Elf32ProgramHeader>,
    /// Parsed section headers
    section_headers: Vec<Elf32SectionHeader>,
    /// Section name string table (if available)
    section_names: Option<Vec<u8>>,
    /// Symbol table entries (if available)
    symbols: Vec<Elf32Symbol>,
    /// Symbol string table (if available)
    symbol_names: Option<Vec<u8>>,
}

impl ElfLoader {
    /// Parse an ELF file from bytes.
    ///
    /// Validates the ELF header, parses program headers (for loading),
    /// and optionally parses section headers (for symbols/debugging).
    ///
    /// # Errors
    ///
    /// Returns `InvalidElf` if:
    /// - File is too small to contain ELF header
    /// - Magic number is incorrect
    /// - Not a 32-bit little-endian ELF
    /// - Not a RISC-V executable
    /// - Headers are malformed or out of bounds
    pub fn parse(data: &[u8]) -> Result<Self, ExecutorError> {
        // Validate minimum size for ELF header
        if data.len() < ELF32_HEADER_SIZE {
            return Err(ExecutorError::InvalidElf(format!(
                "File too small: {} bytes (need at least {})",
                data.len(),
                ELF32_HEADER_SIZE
            )));
        }

        // Validate ELF magic number
        if data[0..4] != ELF_MAGIC {
            return Err(ExecutorError::InvalidElf(format!(
                "Invalid magic: {:02x} {:02x} {:02x} {:02x}",
                data[0], data[1], data[2], data[3]
            )));
        }

        // Validate 32-bit class
        if data[4] != ELFCLASS32 {
            return Err(ExecutorError::InvalidElf(format!(
                "Not 32-bit ELF (class: {})",
                data[4]
            )));
        }

        // Validate little-endian encoding
        if data[5] != ELFDATA2LSB {
            return Err(ExecutorError::InvalidElf(format!(
                "Not little-endian (encoding: {})",
                data[5]
            )));
        }

        // Validate ELF version in e_ident
        if data[6] != EV_CURRENT {
            return Err(ExecutorError::InvalidElf(format!(
                "Unsupported ELF version in ident: {}",
                data[6]
            )));
        }

        // Parse header fields
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        let e_version = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // Validate ELF type (executable or shared object)
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(ExecutorError::InvalidElf(format!(
                "Not an executable (type: {})",
                e_type
            )));
        }

        // Validate machine type
        if e_machine != EM_RISCV {
            return Err(ExecutorError::InvalidElf(format!(
                "Not RISC-V (machine: {})",
                e_machine
            )));
        }

        // Validate version
        if e_version != 1 {
            return Err(ExecutorError::InvalidElf(format!(
                "Unsupported ELF version: {}",
                e_version
            )));
        }

        // Parse full header
        let header = Elf32Header {
            e_type,
            e_machine,
            e_version,
            entry: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            phoff: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            shoff: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            flags: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            ehsize: u16::from_le_bytes([data[40], data[41]]),
            phentsize: u16::from_le_bytes([data[42], data[43]]),
            phnum: u16::from_le_bytes([data[44], data[45]]),
            shentsize: u16::from_le_bytes([data[46], data[47]]),
            shnum: u16::from_le_bytes([data[48], data[49]]),
            shstrndx: u16::from_le_bytes([data[50], data[51]]),
        };

        // Validate header size
        if header.ehsize as usize != ELF32_HEADER_SIZE {
            return Err(ExecutorError::InvalidElf(format!(
                "Invalid ELF header size: {}",
                header.ehsize
            )));
        }

        // Parse program headers
        let program_headers = Self::parse_program_headers(data, &header)?;

        // Parse section headers (optional, for symbols)
        let section_headers = Self::parse_section_headers(data, &header)?;

        // Load section name string table
        let section_names = Self::load_section_strtab(data, &header, &section_headers);

        // Parse symbol table
        let (symbols, symbol_names) = Self::parse_symbol_table(data, &section_headers);

        Ok(Self {
            data: data.to_vec(),
            header,
            program_headers,
            section_headers,
            section_names,
            symbols,
            symbol_names,
        })
    }

    /// Parse program headers from ELF data.
    fn parse_program_headers(
        data: &[u8],
        header: &Elf32Header,
    ) -> Result<Vec<Elf32ProgramHeader>, ExecutorError> {
        let mut headers = Vec::with_capacity(header.phnum as usize);
        let phoff = header.phoff as usize;
        let phentsize = header.phentsize as usize;

        // Validate program header entry size
        if phentsize < ELF32_PHDR_SIZE {
            return Err(ExecutorError::InvalidElf(format!(
                "Program header size too small: {}",
                phentsize
            )));
        }

        for i in 0..header.phnum as usize {
            let offset = phoff + i * phentsize;

            if offset + ELF32_PHDR_SIZE > data.len() {
                return Err(ExecutorError::InvalidElf(format!(
                    "Program header {} out of bounds (offset {})",
                    i, offset
                )));
            }

            let ph = Elf32ProgramHeader {
                p_type: u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]),
                p_offset: u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]),
                p_vaddr: u32::from_le_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]),
                p_paddr: u32::from_le_bytes([
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                ]),
                p_filesz: u32::from_le_bytes([
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19],
                ]),
                p_memsz: u32::from_le_bytes([
                    data[offset + 20],
                    data[offset + 21],
                    data[offset + 22],
                    data[offset + 23],
                ]),
                p_flags: u32::from_le_bytes([
                    data[offset + 24],
                    data[offset + 25],
                    data[offset + 26],
                    data[offset + 27],
                ]),
                p_align: u32::from_le_bytes([
                    data[offset + 28],
                    data[offset + 29],
                    data[offset + 30],
                    data[offset + 31],
                ]),
            };

            headers.push(ph);
        }

        Ok(headers)
    }

    /// Parse section headers from ELF data.
    fn parse_section_headers(
        data: &[u8],
        header: &Elf32Header,
    ) -> Result<Vec<Elf32SectionHeader>, ExecutorError> {
        // Section headers are optional
        if header.shoff == 0 || header.shnum == 0 {
            return Ok(Vec::new());
        }

        let mut headers = Vec::with_capacity(header.shnum as usize);
        let shoff = header.shoff as usize;
        let shentsize = header.shentsize as usize;

        // Validate section header entry size
        if shentsize < ELF32_SHDR_SIZE {
            return Err(ExecutorError::InvalidElf(format!(
                "Section header size too small: {}",
                shentsize
            )));
        }

        for i in 0..header.shnum as usize {
            let offset = shoff + i * shentsize;

            if offset + ELF32_SHDR_SIZE > data.len() {
                // Section headers truncated - this is common in stripped binaries
                break;
            }

            let sh = Elf32SectionHeader {
                sh_name: u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]),
                sh_type: u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]),
                sh_flags: u32::from_le_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]),
                sh_addr: u32::from_le_bytes([
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                ]),
                sh_offset: u32::from_le_bytes([
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19],
                ]),
                sh_size: u32::from_le_bytes([
                    data[offset + 20],
                    data[offset + 21],
                    data[offset + 22],
                    data[offset + 23],
                ]),
                sh_link: u32::from_le_bytes([
                    data[offset + 24],
                    data[offset + 25],
                    data[offset + 26],
                    data[offset + 27],
                ]),
                sh_info: u32::from_le_bytes([
                    data[offset + 28],
                    data[offset + 29],
                    data[offset + 30],
                    data[offset + 31],
                ]),
                sh_addralign: u32::from_le_bytes([
                    data[offset + 32],
                    data[offset + 33],
                    data[offset + 34],
                    data[offset + 35],
                ]),
                sh_entsize: u32::from_le_bytes([
                    data[offset + 36],
                    data[offset + 37],
                    data[offset + 38],
                    data[offset + 39],
                ]),
            };

            headers.push(sh);
        }

        Ok(headers)
    }

    /// Load section name string table.
    fn load_section_strtab(
        data: &[u8],
        header: &Elf32Header,
        sections: &[Elf32SectionHeader],
    ) -> Option<Vec<u8>> {
        let idx = header.shstrndx as usize;
        if idx >= sections.len() {
            return None;
        }

        let strtab = &sections[idx];
        if strtab.sh_type != SHT_STRTAB {
            return None;
        }

        let start = strtab.sh_offset as usize;
        let size = strtab.sh_size as usize;

        if start + size <= data.len() {
            Some(data[start..start + size].to_vec())
        } else {
            None
        }
    }

    /// Parse symbol table from section headers.
    fn parse_symbol_table(
        data: &[u8],
        sections: &[Elf32SectionHeader],
    ) -> (Vec<Elf32Symbol>, Option<Vec<u8>>) {
        // Find symbol table section (.symtab or .dynsym)
        let symtab = sections
            .iter()
            .find(|s| s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM);

        let symtab = match symtab {
            Some(s) => s,
            None => return (Vec::new(), None),
        };

        // Get associated string table
        let strtab_idx = symtab.sh_link as usize;
        let strtab = if strtab_idx < sections.len() {
            let s = &sections[strtab_idx];
            let start = s.sh_offset as usize;
            let size = s.sh_size as usize;
            if start + size <= data.len() {
                Some(data[start..start + size].to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // Parse symbols
        let mut symbols = Vec::new();
        let start = symtab.sh_offset as usize;
        let size = symtab.sh_size as usize;
        let entsize = if symtab.sh_entsize > 0 {
            symtab.sh_entsize as usize
        } else {
            ELF32_SYM_SIZE
        };

        if entsize < ELF32_SYM_SIZE || start + size > data.len() {
            return (Vec::new(), strtab);
        }

        let num_symbols = size / entsize;
        for i in 0..num_symbols {
            let offset = start + i * entsize;
            if offset + ELF32_SYM_SIZE > data.len() {
                break;
            }

            let sym = Elf32Symbol {
                st_name: u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]),
                st_value: u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]),
                st_size: u32::from_le_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]),
                st_info: data[offset + 12],
                st_other: data[offset + 13],
                st_shndx: u16::from_le_bytes([data[offset + 14], data[offset + 15]]),
            };

            symbols.push(sym);
        }

        (symbols, strtab)
    }

    /// Get the entry point address.
    pub fn entry_point(&self) -> u32 {
        self.header.entry
    }

    /// Get all loadable segments (PT_LOAD).
    pub fn loadable_segments(&self) -> impl Iterator<Item = &Elf32ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
    }

    /// Load the ELF into memory.
    ///
    /// Loads all PT_LOAD segments into memory:
    /// - Copies file data to memory at virtual addresses
    /// - Zero-fills BSS regions (memsz > filesz)
    ///
    /// Returns the entry point address on success.
    pub fn load_into_memory(&self, memory: &mut Memory) -> Result<u32, ExecutorError> {
        // Sort segments by virtual address to handle overlaps correctly
        let mut segments: Vec<_> = self.loadable_segments().collect();
        segments.sort_by_key(|s| s.p_vaddr);

        for ph in segments {
            let file_offset = ph.p_offset as usize;
            let file_size = ph.p_filesz as usize;
            let mem_addr = ph.p_vaddr;
            let mem_size = ph.p_memsz as usize;

            // Validate file bounds
            if file_size > 0 && file_offset.saturating_add(file_size) > self.data.len() {
                return Err(ExecutorError::InvalidElf(format!(
                    "Segment at 0x{:08x} data out of bounds",
                    mem_addr
                )));
            }

            // Validate memory size is at least file size
            if mem_size < file_size {
                return Err(ExecutorError::InvalidElf(format!(
                    "Segment at 0x{:08x} has memsz < filesz",
                    mem_addr
                )));
            }

            // Load file data into memory
            if file_size > 0 {
                let segment_data = &self.data[file_offset..file_offset + file_size];
                memory.load_program(mem_addr, segment_data)?;
            }

            // Zero-fill BSS section (memsz > filesz)
            // This is more efficient than byte-by-byte writes
            if mem_size > file_size {
                let bss_start = mem_addr.saturating_add(file_size as u32);
                let bss_size = mem_size - file_size;
                let zeros = vec![0u8; bss_size];
                memory.load_program(bss_start, &zeros)?;
            }
        }

        Ok(self.entry_point())
    }

    /// Get memory bounds (lowest and highest addresses needed).
    pub fn memory_bounds(&self) -> (u32, u32) {
        let mut low = u32::MAX;
        let mut high = 0u32;

        for ph in self.loadable_segments() {
            low = low.min(ph.p_vaddr);
            high = high.max(ph.p_vaddr.saturating_add(ph.p_memsz));
        }

        if low == u32::MAX {
            (0, 0)
        } else {
            (low, high)
        }
    }

    /// Get total memory size needed for all segments.
    pub fn total_memory_size(&self) -> u32 {
        let (low, high) = self.memory_bounds();
        high.saturating_sub(low)
    }

    /// Get ELF header.
    pub fn header(&self) -> &Elf32Header {
        &self.header
    }

    /// Get program headers.
    pub fn program_headers(&self) -> &[Elf32ProgramHeader] {
        &self.program_headers
    }

    /// Get section headers.
    pub fn section_headers(&self) -> &[Elf32SectionHeader] {
        &self.section_headers
    }

    /// Get symbols (if symbol table present).
    pub fn symbols(&self) -> &[Elf32Symbol] {
        &self.symbols
    }

    /// Get a section name by index.
    pub fn section_name(&self, sh_name: u32) -> Option<&str> {
        let strtab = self.section_names.as_ref()?;
        let start = sh_name as usize;
        if start >= strtab.len() {
            return None;
        }

        // Find null terminator
        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| start + pos)
            .unwrap_or(strtab.len());

        std::str::from_utf8(&strtab[start..end]).ok()
    }

    /// Get a symbol name.
    pub fn symbol_name(&self, st_name: u32) -> Option<&str> {
        let strtab = self.symbol_names.as_ref()?;
        let start = st_name as usize;
        if start >= strtab.len() {
            return None;
        }

        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| start + pos)
            .unwrap_or(strtab.len());

        std::str::from_utf8(&strtab[start..end]).ok()
    }

    /// Find a symbol by name.
    pub fn find_symbol(&self, name: &str) -> Option<&Elf32Symbol> {
        self.symbols
            .iter()
            .find(|s| self.symbol_name(s.st_name) == Some(name))
    }

    /// Find a symbol by address.
    pub fn find_symbol_at(&self, addr: u32) -> Option<(&Elf32Symbol, &str)> {
        for sym in &self.symbols {
            if sym.st_value <= addr && addr < sym.st_value + sym.st_size {
                if let Some(name) = self.symbol_name(sym.st_name) {
                    return Some((sym, name));
                }
            }
        }
        None
    }

    /// Check if this is a position-independent executable.
    pub fn is_pie(&self) -> bool {
        self.header.e_type == ET_DYN
    }

    /// Get RISC-V ISA flags from ELF header.
    /// Returns (RVC compressed support, other flags).
    pub fn riscv_flags(&self) -> (bool, u32) {
        let rvc = (self.header.flags & 0x1) != 0; // RVC extension
        (rvc, self.header.flags)
    }
}

// ============================================================================
// ELF Flags and Constants (Public API)
// ============================================================================

/// ELF section flags.
pub mod section_flags {
    /// Section is writable.
    pub const SHF_WRITE: u32 = 0x1;
    /// Section occupies memory during execution.
    pub const SHF_ALLOC: u32 = 0x2;
    /// Section is executable.
    pub const SHF_EXECINSTR: u32 = 0x4;
    /// Section may be merged.
    pub const SHF_MERGE: u32 = 0x10;
    /// Section contains null-terminated strings.
    pub const SHF_STRINGS: u32 = 0x20;
    /// Section holds info link.
    pub const SHF_INFO_LINK: u32 = 0x40;
    /// Preserve section order after combining.
    pub const SHF_LINK_ORDER: u32 = 0x80;
    /// Section holds thread-local storage.
    pub const SHF_TLS: u32 = 0x400;
}

/// ELF segment flags.
pub mod segment_flags {
    /// Segment is executable.
    pub const PF_X: u32 = 0x1;
    /// Segment is writable.
    pub const PF_W: u32 = 0x2;
    /// Segment is readable.
    pub const PF_R: u32 = 0x4;
}

/// Symbol binding values.
pub mod symbol_binding {
    /// Local symbol (not visible outside the object file).
    pub const STB_LOCAL: u8 = 0;
    /// Global symbol (visible to all object files).
    pub const STB_GLOBAL: u8 = 1;
    /// Weak symbol (like global, but lower precedence).
    pub const STB_WEAK: u8 = 2;
}

/// Symbol type values.
pub mod symbol_type {
    /// No type.
    pub const STT_NOTYPE: u8 = 0;
    /// Data object.
    pub const STT_OBJECT: u8 = 1;
    /// Function.
    pub const STT_FUNC: u8 = 2;
    /// Section.
    pub const STT_SECTION: u8 = 3;
    /// Source file.
    pub const STT_FILE: u8 = 4;
}

// ============================================================================
// Test ELF Builder
// ============================================================================

/// Build a minimal ELF file for testing.
///
/// Creates a valid ELF32 RISC-V executable with:
/// - ELF header
/// - One program header (PT_LOAD)
/// - Code segment
///
/// # Arguments
/// - `code`: Machine code bytes to include
/// - `entry`: Entry point address
/// - `load_addr`: Virtual address where code is loaded
pub fn build_test_elf(code: &[u8], entry: u32, load_addr: u32) -> Vec<u8> {
    // Align code segment to 4 bytes
    let code_padded_len = (code.len() + 3) & !3;

    let mut elf = Vec::with_capacity(ELF32_HEADER_SIZE + ELF32_PHDR_SIZE + code_padded_len);

    // ELF header (52 bytes)
    elf.extend_from_slice(&ELF_MAGIC); // e_ident[0..4]: Magic
    elf.push(ELFCLASS32); // e_ident[4]: Class (32-bit)
    elf.push(ELFDATA2LSB); // e_ident[5]: Data (little-endian)
    elf.push(EV_CURRENT); // e_ident[6]: Version
    elf.push(0); // e_ident[7]: OS/ABI (SYSV)
    elf.extend_from_slice(&[0u8; 8]); // e_ident[8..16]: Padding
    elf.extend_from_slice(&ET_EXEC.to_le_bytes()); // e_type: Executable
    elf.extend_from_slice(&EM_RISCV.to_le_bytes()); // e_machine: RISC-V
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
    elf.extend_from_slice(&(ELF32_HEADER_SIZE as u32).to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_shoff (no section headers)
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&(ELF32_HEADER_SIZE as u16).to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&(ELF32_PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum (1 program header)
    elf.extend_from_slice(&(ELF32_SHDR_SIZE as u16).to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum (no sections)
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    // Program header (32 bytes)
    let code_offset = ELF32_HEADER_SIZE + ELF32_PHDR_SIZE;
    elf.extend_from_slice(&PT_LOAD.to_le_bytes()); // p_type
    elf.extend_from_slice(&(code_offset as u32).to_le_bytes()); // p_offset
    elf.extend_from_slice(&load_addr.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&load_addr.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&(code.len() as u32).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(code.len() as u32).to_le_bytes()); // p_memsz
    elf.extend_from_slice(&(segment_flags::PF_R | segment_flags::PF_X).to_le_bytes()); // p_flags
    elf.extend_from_slice(&4u32.to_le_bytes()); // p_align

    // Code segment
    elf.extend_from_slice(code);

    // Pad to 4-byte alignment
    while elf.len() % 4 != 0 {
        elf.push(0);
    }

    elf
}

/// Build an ELF with multiple segments (code + data + BSS) for testing.
pub fn build_test_elf_with_data(
    code: &[u8],
    data: &[u8],
    bss_size: u32,
    entry: u32,
    code_addr: u32,
    data_addr: u32,
) -> Vec<u8> {
    let num_phdrs = 2; // code + data/bss
    let phdrs_size = num_phdrs * ELF32_PHDR_SIZE;
    let code_offset = ELF32_HEADER_SIZE + phdrs_size;
    let data_offset = code_offset + ((code.len() + 3) & !3); // Aligned

    let mut elf = Vec::new();

    // ELF header
    elf.extend_from_slice(&ELF_MAGIC);
    elf.push(ELFCLASS32);
    elf.push(ELFDATA2LSB);
    elf.push(EV_CURRENT);
    elf.push(0);
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&ET_EXEC.to_le_bytes());
    elf.extend_from_slice(&EM_RISCV.to_le_bytes());
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&entry.to_le_bytes());
    elf.extend_from_slice(&(ELF32_HEADER_SIZE as u32).to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&(ELF32_HEADER_SIZE as u16).to_le_bytes());
    elf.extend_from_slice(&(ELF32_PHDR_SIZE as u16).to_le_bytes());
    elf.extend_from_slice(&(num_phdrs as u16).to_le_bytes());
    elf.extend_from_slice(&(ELF32_SHDR_SIZE as u16).to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());
    elf.extend_from_slice(&0u16.to_le_bytes());

    // Program header 1: Code (PT_LOAD, R+X)
    elf.extend_from_slice(&PT_LOAD.to_le_bytes());
    elf.extend_from_slice(&(code_offset as u32).to_le_bytes());
    elf.extend_from_slice(&code_addr.to_le_bytes());
    elf.extend_from_slice(&code_addr.to_le_bytes());
    elf.extend_from_slice(&(code.len() as u32).to_le_bytes());
    elf.extend_from_slice(&(code.len() as u32).to_le_bytes());
    elf.extend_from_slice(&(segment_flags::PF_R | segment_flags::PF_X).to_le_bytes());
    elf.extend_from_slice(&4u32.to_le_bytes());

    // Program header 2: Data + BSS (PT_LOAD, R+W)
    let memsz = data.len() as u32 + bss_size;
    elf.extend_from_slice(&PT_LOAD.to_le_bytes());
    elf.extend_from_slice(&(data_offset as u32).to_le_bytes());
    elf.extend_from_slice(&data_addr.to_le_bytes());
    elf.extend_from_slice(&data_addr.to_le_bytes());
    elf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // filesz
    elf.extend_from_slice(&memsz.to_le_bytes()); // memsz (includes BSS)
    elf.extend_from_slice(&(segment_flags::PF_R | segment_flags::PF_W).to_le_bytes());
    elf.extend_from_slice(&4u32.to_le_bytes());

    // Code segment
    elf.extend_from_slice(code);
    while elf.len() < data_offset {
        elf.push(0);
    }

    // Data segment
    elf.extend_from_slice(data);

    elf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_elf() {
        // Simple RISC-V code: addi x1, x0, 42; ecall
        let code = vec![
            0x93, 0x00, 0xa0, 0x02, // addi x1, x0, 42
            0x73, 0x00, 0x00, 0x00, // ecall
        ];

        let elf_data = build_test_elf(&code, 0x1000, 0x1000);
        let loader = ElfLoader::parse(&elf_data).expect("Failed to parse ELF");

        assert_eq!(loader.entry_point(), 0x1000);
        assert_eq!(loader.loadable_segments().count(), 1);
        assert_eq!(loader.header().e_type, ET_EXEC);
        assert_eq!(loader.header().e_machine, EM_RISCV);
    }

    #[test]
    fn test_load_into_memory() {
        let code = vec![
            0x93, 0x00, 0xa0, 0x02, // addi x1, x0, 42
            0x73, 0x00, 0x00, 0x00, // ecall
        ];

        let elf_data = build_test_elf(&code, 0x1000, 0x1000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        let mut memory = Memory::with_default_size();
        let entry = loader.load_into_memory(&mut memory).unwrap();

        assert_eq!(entry, 0x1000);

        // Verify code was loaded
        let instr = memory.read_u32(0x1000).unwrap();
        assert_eq!(instr, 0x02a00093); // addi x1, x0, 42
    }

    #[test]
    fn test_invalid_elf_magic() {
        // 52 bytes (minimum ELF header size) but wrong magic
        let mut bad_data = vec![0x00; 52];
        bad_data[0] = 0xDE;
        bad_data[1] = 0xAD;
        bad_data[2] = 0xBE;
        bad_data[3] = 0xEF;
        let result = ElfLoader::parse(&bad_data);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("magic") || err_msg.contains("Magic"),
            "Expected 'magic' in error: {}",
            err_msg
        );
    }

    #[test]
    fn test_invalid_elf_too_small() {
        let bad_data = vec![0x7f, b'E', b'L', b'F'];
        let result = ElfLoader::parse(&bad_data);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("small") || err_msg.contains("bytes"),
            "Expected size-related error: {}",
            err_msg
        );
    }

    #[test]
    fn test_memory_bounds() {
        let code = vec![0x00; 100];
        let elf_data = build_test_elf(&code, 0x2000, 0x2000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        let (low, high) = loader.memory_bounds();
        assert_eq!(low, 0x2000);
        assert_eq!(high, 0x2000 + 100);
        assert_eq!(loader.total_memory_size(), 100);
    }

    #[test]
    fn test_elf_with_data_and_bss() {
        let code = vec![
            0x93, 0x00, 0xa0, 0x02, // addi x1, x0, 42
        ];
        let data = vec![0x11, 0x22, 0x33, 0x44];
        let bss_size = 16;

        let elf_data = build_test_elf_with_data(&code, &data, bss_size, 0x1000, 0x1000, 0x2000);

        let loader = ElfLoader::parse(&elf_data).unwrap();

        assert_eq!(loader.entry_point(), 0x1000);
        assert_eq!(loader.loadable_segments().count(), 2);

        let mut memory = Memory::with_default_size();
        loader.load_into_memory(&mut memory).unwrap();

        // Verify code
        let instr = memory.read_u32(0x1000).unwrap();
        assert_eq!(instr, 0x02a00093);

        // Verify data
        assert_eq!(memory.read_u8(0x2000).unwrap(), 0x11);
        assert_eq!(memory.read_u8(0x2001).unwrap(), 0x22);
        assert_eq!(memory.read_u8(0x2002).unwrap(), 0x33);
        assert_eq!(memory.read_u8(0x2003).unwrap(), 0x44);

        // Verify BSS is zeroed
        for i in 0..bss_size {
            assert_eq!(
                memory.read_u8(0x2004 + i).unwrap(),
                0,
                "BSS byte {} not zero",
                i
            );
        }
    }

    #[test]
    fn test_memory_bounds_empty() {
        // Create a minimal ELF with no PT_LOAD segments
        let mut elf = vec![0u8; 52];
        elf[0..4].copy_from_slice(&ELF_MAGIC);
        elf[4] = ELFCLASS32;
        elf[5] = ELFDATA2LSB;
        elf[6] = 1; // version
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_RISCV.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        elf[40..42].copy_from_slice(&52u16.to_le_bytes()); // ehsize
        elf[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
        elf[46..48].copy_from_slice(&40u16.to_le_bytes()); // shentsize

        let loader = ElfLoader::parse(&elf).unwrap();
        let (low, high) = loader.memory_bounds();
        assert_eq!(low, 0);
        assert_eq!(high, 0);
        assert_eq!(loader.total_memory_size(), 0);
    }

    #[test]
    fn test_segment_flags() {
        use segment_flags::*;

        let code = vec![0x00; 4];
        let elf_data = build_test_elf(&code, 0x1000, 0x1000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        let seg = loader.loadable_segments().next().unwrap();
        assert!(seg.p_flags & PF_R != 0, "Should be readable");
        assert!(seg.p_flags & PF_X != 0, "Should be executable");
        assert!(seg.p_flags & PF_W == 0, "Should not be writable");
    }

    #[test]
    fn test_is_pie() {
        let code = vec![0x00; 4];
        let elf_data = build_test_elf(&code, 0x1000, 0x1000);
        let loader = ElfLoader::parse(&elf_data).unwrap();
        assert!(!loader.is_pie(), "Standard executable should not be PIE");
    }

    #[test]
    fn test_riscv_flags() {
        let code = vec![0x00; 4];
        let elf_data = build_test_elf(&code, 0x1000, 0x1000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        let (rvc, flags) = loader.riscv_flags();
        assert!(!rvc, "Test ELF has no RVC flag");
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_different_entry_and_load_addr() {
        let code = vec![
            0x00, 0x00, 0x00, 0x00, // nop (padding)
            0x93, 0x00, 0xa0, 0x02, // addi x1, x0, 42 (entry point)
        ];

        // Entry at offset 4 from load address
        let elf_data = build_test_elf(&code, 0x1004, 0x1000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        assert_eq!(loader.entry_point(), 0x1004);

        let mut memory = Memory::with_default_size();
        let entry = loader.load_into_memory(&mut memory).unwrap();
        assert_eq!(entry, 0x1004);

        // Verify the actual entry point instruction
        let instr = memory.read_u32(0x1004).unwrap();
        assert_eq!(instr, 0x02a00093); // addi x1, x0, 42
    }

    #[test]
    fn test_large_segment() {
        // Test loading a larger code segment
        let code: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let elf_data = build_test_elf(&code, 0x10000, 0x10000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        let mut memory = Memory::with_default_size();
        loader.load_into_memory(&mut memory).unwrap();

        // Verify pattern
        for i in 0..1024u32 {
            let expected = (i % 256) as u8;
            let actual = memory.read_u8(0x10000 + i).unwrap();
            assert_eq!(actual, expected, "Mismatch at offset {}", i);
        }
    }

    #[test]
    fn test_elf_header_fields() {
        let code = vec![0x00; 8];
        let elf_data = build_test_elf(&code, 0x80000000, 0x80000000);
        let loader = ElfLoader::parse(&elf_data).unwrap();

        let header = loader.header();
        assert_eq!(header.e_type, ET_EXEC);
        assert_eq!(header.e_machine, EM_RISCV);
        assert_eq!(header.e_version, 1);
        assert_eq!(header.ehsize, ELF32_HEADER_SIZE as u16);
        assert_eq!(header.phentsize, ELF32_PHDR_SIZE as u16);
        assert_eq!(header.phnum, 1);
    }
}
