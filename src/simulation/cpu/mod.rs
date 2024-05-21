pub use crate::elf_file::ElfFile;
use crate::{
    simulation::fault::{SimulationFaultRecord, TraceRecord},
    simulation::{FaultData, FaultType},
};

mod callback;
use callback::*;

use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

use log::debug;
use std::collections::HashSet;

use super::FlagsCPSR;

// Constant variable definitions
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const AUTH_BASE: u64 = 0xAA01000;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr
const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

const ARM_REG: [RegisterARM; 17] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
    RegisterARM::SP,
    RegisterARM::LR,
    RegisterARM::PC,
    RegisterARM::CPSR,
];

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub enum RunState {
    #[default]
    Init = 0,
    Success,
    Failed,
    Error,
}

pub struct Cpu<'a> {
    emu: Unicorn<'a, CpuState<'a>>,
    program_counter: u64,
}

struct CpuState<'a> {
    state: RunState,
    start_trace: bool,
    with_register_data: bool,
    negative_run: bool,
    deactivate_print: bool,
    trace_data: Vec<TraceRecord>,
    fault_data: Vec<FaultData>,
    file_data: &'a ElfFile,
}

impl<'a> Cpu<'a> {
    pub fn new(file_data: &'a ElfFile) -> Self {
        // Setup platform -> ARMv8-m.base
        let emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            CpuState {
                state: Default::default(),
                start_trace: false,
                with_register_data: false,
                negative_run: false,
                deactivate_print: false,
                trace_data: Vec::new(),
                fault_data: Vec::new(),
                file_data,
            },
        )
        .expect("failed to initialize Unicorn instance");

        debug!("Setup new unicorn instance");

        Self {
            emu,
            program_counter: 0,
        }
    }

    /// Initialize all required register to zero
    ///
    /// Additionally the SP is set to start of stack
    pub fn init_register(&mut self) {
        // Clear registers
        ARM_REG
            .iter()
            .for_each(|reg| self.emu.reg_write(*reg, 0x00).unwrap());

        // Setup registers
        self.emu
            .reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
            .expect("failed to set register");
    }

    /// Load source code from elf file into simulation
    ///
    /// The PC is set to the start of the program
    pub fn load_code(&mut self) {
        self.emu
            .mem_write(
                self.emu.get_data().file_data.program_header.p_paddr,
                &self.emu.get_data().file_data.program,
            )
            .expect("failed to write file data");
        // set initial program start address
        self.program_counter = self.emu.get_data().file_data.program_header.p_paddr;

        // Write wrong flash data to DECISION_DATA stage memory
        write_decision_element(&mut self.emu, false);
    }

    /// Function to deactivate printf of c program to
    /// avoid unexpected output
    pub fn deactivate_printf_function(&mut self) {
        self.emu.get_data_mut().deactivate_print = true;
        self.emu
            .mem_write(
                self.emu.get_data().file_data.serial_puts.st_value & 0xfffffffe,
                &T1_RET,
            )
            .unwrap();
    }

    /// Setup all breakpoints
    ///
    /// BreakPoints
    /// { binInfo.Symbols["decision_activation"].Address }
    pub fn setup_breakpoints(&mut self) {
        self.emu
            .add_code_hook(
                self.emu.get_data().file_data.decision_activation.st_value,
                self.emu.get_data().file_data.decision_activation.st_value + 1,
                hook_code_decision_activation_callback,
            )
            .expect("failed to set decision_activation code hook");

        self.emu
            .add_mem_hook(
                HookType::MEM_WRITE,
                AUTH_BASE,
                AUTH_BASE + 4,
                mmio_auth_write_callback,
            )
            .expect("failed to set memory hook");
    }

    /// Setup memory mapping, stack, io mapping
    pub fn setup_mmio(&mut self) {
        const MINIMUM_MEMORY_SIZE: usize = 0x1000;
        // Code
        let code_size =
            (self.emu.get_data().file_data.program.len() + MINIMUM_MEMORY_SIZE) & 0xfffff000;
        self.emu
            .mem_map(
                self.emu.get_data().file_data.program_header.p_paddr,
                code_size,
                Permission::ALL,
            )
            .expect("failed to map code page");

        // Stack
        self.emu
            .mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)
            .expect("failed to map stack page");

        // Auth success / failed trigger
        self.emu
            .mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Permission::WRITE)
            .expect("failed to map mmio replacement");

        // IO address space
        self.emu
            .mmio_map_wo(0x11000000, MINIMUM_MEMORY_SIZE, mmio_serial_write_callback)
            .expect("failed to map serial IO");
    }

    /// Execute code on pc set in internal structure till cycles
    ///
    /// If debug is set to true, execution is done by single steps
    pub fn run_steps(&mut self, cycles: usize, debug: bool) -> Result<(), uc_error> {
        let mut ret_val;
        if debug {
            let mut cyc = cycles;
            ret_val = Ok(());
            while ret_val == Ok(()) && cyc != 0 {
                //println!("Executing address : 0x{:X}", self.emu.get_data().program_counter);
                ret_val = self.run_steps(1, false);
                cyc -= 1;
                println!("PC : 0x{:X}", self.emu.pc_read().unwrap());
                if self.emu.get_data().state != RunState::Init {
                    println!("Stopped on marker: {:?}", self.emu.get_data().state);
                    break;
                }
            }
        } else {
            let end_address = self.emu.get_data().file_data.program_header.p_paddr
                + self.emu.get_data().file_data.program_header.p_filesz;

            // Start from last PC
            ret_val = self.emu.emu_start(
                self.program_counter | 1,
                end_address | 1,
                SECOND_SCALE,
                cycles,
            );
        }
        // Store new PC
        self.program_counter = self.emu.pc_read().unwrap();

        ret_val
    }

    fn get_asm_cmd_size(&self, address: u64) -> Option<usize> {
        let mut data: [u8; 2] = [0; 2];
        // Check for 32bit cmd (0b11101... 0b1111....)
        if self.emu.mem_read(address, &mut data).is_ok() {
            if (data[1] & 0xF8 == 0xE8) || (data[1] & 0xF0 == 0xF0) {
                return Some(4);
            }
            return Some(2);
        }
        None
    }

    /// Initialize the internal program state
    pub fn init_states(&mut self, run_state: bool) {
        // Set run type
        self.emu.get_data_mut().negative_run = !run_state;

        // Set global state to initilized
        self.emu.get_data_mut().state = RunState::Init;
    }

    /// Get current state of simulation
    pub fn get_state(&self) -> RunState {
        self.emu.get_data().state
    }

    /// Get fault_data
    pub fn get_fault_data(&self) -> &Vec<FaultData> {
        &self.emu.get_data().fault_data
    }

    /// Set code hook for tracing
    pub fn set_trace_hook(&mut self) {
        self.emu
            .add_code_hook(
                self.emu.get_data().file_data.program_header.p_paddr,
                self.emu.get_data().file_data.program_header.p_memsz,
                hook_code_callback,
            )
            .expect("failed to setup trace hook");
    }

    pub fn start_tracing(&mut self, with_register_data: bool) {
        let cpu_state = self.emu.get_data_mut();
        cpu_state.with_register_data = with_register_data;
        cpu_state.start_trace = true;
    }

    /// Clear fault data in internal structure
    pub fn clear_fault_data(&mut self) {
        // Remove hooks from list
        self.emu.get_data_mut().fault_data.clear();
    }

    /// Copy trace data to caller
    pub fn get_trace(&self) -> &Vec<TraceRecord> {
        &self.emu.get_data().trace_data
    }

    /// Remove duplicates to speed up testing
    pub fn reduce_trace(&mut self) {
        let trace_data = &mut self.emu.get_data_mut().trace_data;
        let hash_set: HashSet<TraceRecord> = HashSet::from_iter(trace_data.clone());
        *trace_data = Vec::from_iter(hash_set);
    }

    /// Execute a glitch skipping `n` instructions.
    fn execute_glitch(&mut self, fault: &SimulationFaultRecord) {
        let address = self.program_counter;
        let mut offset = 0;
        let mut manipulated_instructions = Vec::new();

        let n = match fault.fault_type {
            FaultType::Glitch(n) => n,
            _ => 0,
        };
        for _count in 0..n {
            let instruction_size = self.get_asm_cmd_size(address + offset).unwrap();
            manipulated_instructions.extend_from_slice(&T1_NOP[..instruction_size]);
            offset += instruction_size as u64;
        }
        self.program_counter += offset;

        // Set to same size as data_changed
        let mut original_instructions = manipulated_instructions.clone();
        // Read original instructions
        self.emu
            .mem_read(address, &mut original_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: fault.fault_type,
        };
        self.emu.get_data_mut().trace_data.push(record.clone());

        // Push to fault data vector
        self.emu.get_data_mut().fault_data.push(FaultData {
            original_instructions,
            record,
            fault: *fault,
        });
    }

    /// Execute a bit flip
    fn execute_bit_flip(&mut self, flag: FlagsCPSR, fault: &SimulationFaultRecord) {
        let address = self.program_counter;
        // Read registers
        // let mut registers: [u32; 17] = [0; 17];
        // ARM_REG.iter().enumerate().for_each(|(index, register)| {
        //     registers[index] = self.emu.reg_read(*register).unwrap() as u32;
        // });

        let mut reg_val = self.emu.reg_read(RegisterARM::CPSR).unwrap();

        reg_val ^= 1 << (flag as u32);

        self.emu.reg_write(RegisterARM::CPSR, reg_val).expect("msg");

        let mut original_instructions = vec![0x00, 0x00];

        self.emu
            .mem_read(address, &mut original_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: fault.fault_type,
        };
        self.emu.get_data_mut().trace_data.push(record.clone());

        // Push to fault data vector
        self.emu.get_data_mut().fault_data.push(FaultData {
            original_instructions,
            record,
            fault: *fault,
        });
    }

    /// Execute fault injection according to fault type
    /// Program is stopped and will be continued after fault injection
    pub fn execute_fault_injection(&mut self, fault: &SimulationFaultRecord) {
        match fault.fault_type {
            FaultType::Glitch(_) => {
                self.execute_glitch(fault);
            }
            FaultType::BitFlip(flag ) => {
                self.execute_bit_flip(flag, fault)
            }
        }
    }
}
